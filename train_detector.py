#!/usr/bin/env python3
"""train_detector.py — load, train, evaluate (Modules 4 + 5).

    # network-only model (schema 1.0.0, the original dataset)
    python3 train_detector.py

    # contextual model: network + syscall + energy (schema 2.0.0)
    python3 train_detector.py --dataset data/dataset_v2.jsonl \\
            --model-dir models_v2 --report-dir reports_v2

Pipeline (see threat_model.py):
    fingerprint -> XGBoost + incremental model -> probability fusion
                -> threat probability -> threshold logic -> threat label
    fingerprint + XGBoost -> SHAP -> feature impact -> final risk score

Which windows count as an attack  (--labels)
  effective  A window is an attack only if it carries a traffic burst far above
             anything in the benign run (pkt_count > BURST_FACTOR x benign max).
             Default for the schema 1.0.0 dataset, whose manifest labels whole
             run intervals as "malware" although the scan fills only a few windows.
  manifest   Trust the label in the record. Default for schema 2.0.0 datasets,
             which are labelled with label_run.py around each attack command.
             Windows nobody labelled count as normal, except the ones right next
             to an attack window, which are left out.

Scan augmentation
  Training adds volume-scaled copies of the real attack windows
  (threat_model.augment_scans) so the models learn the scan signature rather
  than its size. Augmented rows are only ever used for training.
"""
import argparse
import json
import math
import os
import time

import numpy as np
import sklearn
import xgboost
from sklearn.model_selection import StratifiedKFold
from sklearn.svm import OneClassSVM

from common import SCHEMAS, load_records, monitor_of, to_vector
from threat_model import HAVE_SHAP, ThreatModel

BURST_FACTOR = 5.0       # attack burst = > 5x the busiest benign window
SEED = 0


def effective_labels(recs, X, order, benign_max=None):
    lab = np.array([r["label"] for r in recs])
    pk = X[:, order.index("pkt_count")]
    if benign_max is None:
        if not (lab == "benign").any():
            raise SystemExit("--labels effective needs windows labelled benign")
        benign_max = pk[lab == "benign"].max()
    burst_thr = BURST_FACTOR * benign_max
    attack = (pk > burst_thr) & (lab != "benign")
    return lab, attack, float(benign_max), float(burst_thr)


def metrics(y_true, y_pred):
    y_true = np.asarray(y_true, bool); y_pred = np.asarray(y_pred, bool)
    tp = int((y_true & y_pred).sum()); fp = int((~y_true & y_pred).sum())
    fn = int((y_true & ~y_pred).sum()); tn = int((~y_true & ~y_pred).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "accuracy": (tp + tn) / max(1, len(y_true)),
            "precision": p, "recall": r,
            "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0}


def holdout_by_run(recs, usable):
    """Hold out the last ~30% of runs of each label (whole runs, so windows of one
    run never sit on both sides). Returns a boolean test mask."""
    test = np.zeros(len(recs), bool)
    # windows nobody labelled have no run_id: each unbroken stretch of them is one "run"
    block, key, prev = 0, {}, None
    for i, r in enumerate(recs):
        if r.get("run_id"):
            key[i] = r["run_id"]
        else:
            if prev is not None and (recs[prev].get("run_id") or prev != i - 1):
                block += 1
            key[i] = "idle-%d" % block
        prev = i
    for label in sorted({r["label"] for r, u in zip(recs, usable) if u}):
        runs = {}
        for i, r in enumerate(recs):
            if usable[i] and r["label"] == label:
                runs.setdefault(key[i], []).append(i)
        order = sorted(runs, key=lambda k: recs[runs[k][0]]["window_start_epoch"])
        if len(order) >= 2:
            for k in order[-max(1, int(math.ceil(0.3 * len(order)))):]:
                test[runs[k]] = True
    return test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset.jsonl")
    ap.add_argument("--live", default="data/live_fingerprints.jsonl",
                    help="recorded live-stream sample, used if it exists and has the dataset's schema")
    ap.add_argument("--labels", choices=["auto", "effective", "manifest"], default="auto")
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--report-dir", default="reports")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args()

    recs = load_records(a.dataset)
    if not recs:
        raise SystemExit("%s has no usable windows" % a.dataset)
    schema = recs[0]["schema_version"]
    order = list(SCHEMAS[schema])
    X = np.array([to_vector(r, order) for r in recs])
    ids = np.array([r["window_id"] for r in recs])
    lab = np.array([r["label"] for r in recs])
    mode = a.labels if a.labels != "auto" else ("effective" if schema == "1.0.0" else "manifest")
    # Windows labelled "healing" are the device being restored and booting. In manifest
    # mode they are kept as NORMAL traffic: a reboot is not an attack, and a detector that
    # has never seen one flags the first minutes after its own heal and restores again.
    if mode == "effective":
        recs = [r for r in recs if r["label"] != "healing"]
    X = np.array([to_vector(r, order) for r in recs])
    ids = np.array([r["window_id"] for r in recs])
    lab = np.array([r["label"] for r in recs])

    def new_model():
        return ThreatModel(feature_order=order)

    benign_max = burst_thr = None
    if mode == "effective":
        lab, attack, benign_max, burst_thr = effective_labels(recs, X, order)
        usable = np.ones(len(recs), bool)          # every window has an effective label
        train = lab != "unlabeled"                 # train on the labelled runs ...
        test = ~train                              # ... test on the never-seen unlabeled windows
    else:
        attack = lab == "malware"
        # Windows nobody labelled were recorded with no attack tool running, so they are
        # normal traffic (mostly the idle device) and the model must learn them, or it
        # would flag an idle device. Exception: an unlabeled window right next to an
        # attack window may hold the first or last packets of that attack - left out.
        t = np.array([r["window_start_epoch"] for r in recs])
        w = float(recs[0]["window_end_epoch"] - recs[0]["window_start_epoch"]) or 5.0
        near = np.array([bool(attack.any()) and bool((np.abs(t[attack] - ti) <= 1.5 * w).any()) for ti in t])
        guard = (lab == "unlabeled") & near
        usable = ~guard
        test = holdout_by_run(recs, usable)
        train = usable & ~test
    y = attack.astype(int)

    n_att, n_norm = int(attack[usable].sum()), int((~attack)[usable].sum())
    if n_att < 2 or n_norm < 2:
        raise SystemExit("need at least 2 attack and 2 normal windows to train (have %d attack, %d normal). "
                         "Record more labelled runs." % (n_att, n_norm))
    if attack[train].sum() == 0 or (~attack)[train].sum() == 0:    # too few runs to hold any out
        train, test = usable.copy(), np.zeros(len(recs), bool)

    tm = new_model().fit(X[train], y[train])
    T = tm.cfg["t_malicious"]
    px, pi = tm.p_xgb(X), tm.p_inc(X)
    pf = tm.fuse(px, pi)

    MAIN = "fused XGBoost + incremental"
    res = {}
    has_test = bool(attack[test].sum()) and bool((~attack)[test].sum())
    if has_test:
        res[MAIN] = metrics(attack[test], pf[test] >= T)
        res["XGBoost alone"] = metrics(attack[test], px[test] >= 0.5)
        res["incremental model alone"] = metrics(attack[test], pi[test] >= 0.5)
        if mode == "effective":
            raw = new_model().fit(X[train], (lab[train] == "malware").astype(int), augment=False)
            res["fused, trained on RAW manifest labels"] = metrics(
                attack[test], raw.threat_probability(X[test]) >= T)
        oc = OneClassSVM(nu=0.05, gamma="scale").fit(X[train & ~attack])
        res["one-class SVM, normal-only (unsupervised baseline)"] = metrics(
            attack[test], -oc.decision_function(X[test]) > 0.36)
        # the contextual question: do syscall + energy add anything over network alone?
        if schema != "1.0.0":
            net = [i for i, k in enumerate(order) if monitor_of(k) == "network"]
            m_net = ThreatModel(feature_order=[order[i] for i in net]).fit(X[train][:, net], y[train])
            res["fused, NETWORK features only"] = metrics(
                attack[test], m_net.threat_probability(X[test][:, net]) >= T)
            ctx = [i for i, k in enumerate(order) if monitor_of(k) != "network"]
            m_ctx = ThreatModel(feature_order=[order[i] for i in ctx]).fit(X[train][:, ctx], y[train], augment=False)
            res["fused, SYSCALL + ENERGY features only"] = metrics(
                attack[test], m_ctx.threat_probability(X[test][:, ctx]) >= T)

    # stratified k-fold over every usable window (each one is tested exactly once)
    U = np.where(usable)[0]
    k = max(2, min(5, n_att))
    cv_p, cv_noaug = np.zeros(len(X)), np.zeros(len(X))
    for tr, te in StratifiedKFold(n_splits=k, shuffle=True, random_state=SEED).split(X[U], y[U]):
        cv_p[U[te]] = new_model().fit(X[U[tr]], y[U[tr]]).threat_probability(X[U[te]])
        cv_noaug[U[te]] = new_model().fit(X[U[tr]], y[U[tr]], augment=False).threat_probability(X[U[te]])
    res["fused, stratified %d-fold over all %d labelled windows" % (k, len(U))] = metrics(attack[U], cv_p[U] >= T)
    res["fused WITHOUT scan augmentation, same %d-fold" % k] = metrics(attack[U], cv_noaug[U] >= T)

    # ---- recorded live-stream sample: never part of the dataset -------------------
    live, XL, lattack = None, None, None
    if a.live and os.path.exists(a.live) and mode == "effective":
        lrecs = load_records(a.live)
        if lrecs and lrecs[0]["schema_version"] == schema:
            XL = np.array([to_vector(r, order) for r in lrecs])
            _, lattack, _, _ = effective_labels(lrecs, XL, order, benign_max)
            m_aug = new_model().fit(X, y)
            m_no = new_model().fit(X, y, augment=False)
            p_aug, p_no = m_aug.threat_probability(XL), m_no.threat_probability(XL)
            res["LIVE sample, trained on dataset only, WITHOUT augmentation"] = metrics(lattack, p_no >= T)
            res["LIVE sample, trained on dataset only, with augmentation"] = metrics(lattack, p_aug >= T)
            live = {"file": a.live, "n_windows": len(lrecs), "n_attack": int(lattack.sum()),
                    "attack_window_ids": [int(r["window_id"]) for r, f in zip(lrecs, lattack) if f],
                    "attack_p_without_augmentation": [round(float(v), 4) for v in p_no[lattack]],
                    "attack_p_with_augmentation": [round(float(v), 4) for v in p_aug[lattack]],
                    "normal_max_p_with_augmentation": float(p_aug[~lattack].max())}

    # ---- the model that is saved: every labelled window we have --------------------
    X_all, y_all = X[usable], y[usable]
    if live:
        X_all, y_all = np.vstack([X_all, XL]), np.r_[y_all, lattack.astype(int)]
    tm_eval = tm
    tm = new_model().fit(X_all, y_all)

    # ---- SHAP: global feature impact, and the share of each monitor ---------------
    sv, base = tm.shap_values(X_all)
    g = np.abs(sv).mean(0)
    global_impact = [{"feature": order[i], "monitor": monitor_of(order[i]), "mean_abs_shap": round(float(g[i]), 4)}
                     for i in np.argsort(-g) if g[i] > 1e-6]
    tot = float(g.sum()) or 1.0
    share = {m: round(float(sum(g[i] for i, f in enumerate(order) if monitor_of(f) == m)) / tot, 4)
             for m in ("network", "syscall", "energy")}
    dead = {m: [f for i, f in enumerate(order) if monitor_of(f) == m and X[:, i].max() <= X[:, i].min()]
            for m in ("network", "syscall", "energy")}

    # how the saved model scores the windows nobody labelled
    unl = None
    if mode == "manifest":
        unl = {"unlabeled_used_as_normal": int(((lab == "unlabeled") & usable).sum()),
               "unlabeled_next_to_an_attack_left_out": int((~usable).sum())}

    # ---- save ------------------------------------------------------------------------
    tm.save(a.model_dir)
    os.makedirs(a.report_dir, exist_ok=True)
    old = os.path.join(a.model_dir, "detector.joblib")       # model file from the first version
    if os.path.exists(old):
        os.remove(old)

    card = {
        "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": a.dataset, "schema_version": schema, "n_features": len(order),
        "n_records": len(recs), "label_mode": mode,
        "manifest_labels": {str(k): int((lab == k).sum()) for k in sorted(set(lab))},
        "attack_windows": n_att, "normal_windows": n_norm,
        "attack_windows_by_manifest_label": {str(k): int(attack[lab == k].sum()) for k in sorted(set(lab))},
        "burst_rule": None if mode != "effective" else {
            "benign_max_pkt_count_norm": benign_max, "factor": BURST_FACTOR, "threshold_norm": burst_thr},
        "models": {"xgboost": "XGBClassifier(n_estimators=150, max_depth=2, learning_rate=0.1, "
                              "colsample_bytree=0.3, scale_pos_weight=neg/pos)",
                   "incremental": "SGDClassifier(loss=log_loss) trained with partial_fit"},
        "fusion": {"w_xgb": tm.cfg["w_xgb"], "w_inc": tm.cfg["w_inc"]},
        "thresholds": {"suspicious": tm.cfg["t_suspicious"], "malicious": T},
        "scan_augmentation": "volume-scaled copies of real attack windows, training only",
        "n_train": int(train.sum()), "n_train_attack": int(attack[train].sum()),
        "n_test": int(test.sum()), "n_test_attack": int(attack[test].sum()),
        "test_split": ("unlabeled windows" if mode == "effective" else "last 30% of runs per label") if has_test
                      else "none (too few runs) - rely on the k-fold rows",
        "test_normal_max_threat_probability": float(pf[test & ~attack].max()) if has_test else None,
        "test_attack_min_threat_probability": float(pf[test & attack].min()) if has_test else None,
        "cv_folds": k,
        "cv_attack_min_p_with_augmentation": float(cv_p[U][attack[U]].min()),
        "cv_attack_min_p_without_augmentation": float(cv_noaug[U][attack[U]].min()),
        "cv_normal_max_p_with_augmentation": float(cv_p[U][~attack[U]].max()),
        "live_sample": live, "unlabeled_windows": unl,
        "saved_model": {"n_real_windows": int(len(X_all)), "n_real_attack": int(y_all.sum()),
                        "n_rows_after_augmentation": int(tm.n_fit_)},
        "shap_backend": "shap.TreeExplainer" if HAVE_SHAP else "xgboost pred_contribs (TreeSHAP)",
        "shap_base_value": base, "shap_share_by_monitor": share,
        "constant_features_by_monitor": dead, "global_feature_impact": global_impact,
        "versions": {"xgboost": xgboost.__version__, "sklearn": sklearn.__version__},
        "results": res,
    }
    with open(os.path.join(a.model_dir, "model_card.json"), "w") as f:
        json.dump(card, f, indent=2)

    with open(os.path.join(a.report_dir, "window_scores.csv"), "w") as f:
        f.write("window_id,manifest_label,attack,split,p_xgboost,p_incremental,"
                "threat_probability,threat_label,risk_score\n")
        for i in range(len(recs)):
            f.write("%d,%s,%d,%s,%.6f,%.6f,%.6f,%s,%d\n" % (
                ids[i], lab[i], attack[i], "train" if train[i] else "test" if test[i] else "unused",
                px[i], pi[i], pf[i], tm_eval.label(pf[i]), tm_eval.risk_score(pf[i])))

    # ---- console ---------------------------------------------------------------------
    print("dataset: %s   schema %s   %d features (%s)" % (
        a.dataset, schema, len(order),
        ", ".join("%d %s" % (sum(monitor_of(f) == m for f in order), m) for m in ("network", "syscall", "energy")
                  if any(monitor_of(f) == m for f in order))))
    print("records: %d   manifest labels: %s" % (len(recs), card["manifest_labels"]))
    print("label mode: %s -> %d attack / %d normal windows" % (mode, n_att, n_norm))
    if has_test:
        print("train: %d (%d attack)   test: %d (%d attack, %d normal)   [%s]" % (
            train.sum(), attack[train].sum(), test.sum(), attack[test].sum(), (~attack)[test].sum(),
            card["test_split"]))
        print("held-out threat probability: highest normal %.3f, lowest attack %.3f" % (
            card["test_normal_max_threat_probability"], card["test_attack_min_threat_probability"]))
    else:
        print("no separate test split (too few runs per label) - see the %d-fold rows" % k)
    print("fusion: %.1f x XGBoost + %.1f x incremental   thresholds: suspicious >= %.2f, malicious >= %.2f" % (
        tm.cfg["w_xgb"], tm.cfg["w_inc"], tm.cfg["t_suspicious"], T))
    print("%d-fold lowest attack probability: %.3f with scan augmentation, %.3f without" % (
        k, card["cv_attack_min_p_with_augmentation"], card["cv_attack_min_p_without_augmentation"]))
    if live:
        print("live sample (%d windows, attack at window %s): attack probability %s without augmentation, "
              "%s with; highest normal %.3f" % (
                  live["n_windows"], live["attack_window_ids"], live["attack_p_without_augmentation"],
                  live["attack_p_with_augmentation"], live["normal_max_p_with_augmentation"]))
    if unl:
        print("unlabeled windows: %d used as normal, %d next to an attack left out" % (
            unl["unlabeled_used_as_normal"], unl["unlabeled_next_to_an_attack_left_out"]))
    print("saved model trained on %d real windows (%d attack), %d rows after augmentation" % (
        len(X_all), y_all.sum(), tm.n_fit_))
    print()
    print("%-62s %3s %3s %3s %3s  %5s %5s %5s %5s" % ("evaluation", "TP", "FP", "FN", "TN", "acc", "prec", "rec", "FPR"))
    for name, m in res.items():
        print("%-62s %3d %3d %3d %3d  %5.3f %5.3f %5.3f %5.3f" % (
            name, m["tp"], m["fp"], m["fn"], m["tn"], m["accuracy"], m["precision"], m["recall"],
            m["false_positive_rate"]))
    print("\nSHAP feature impact on XGBoost (mean |SHAP|, %s):" % card["shap_backend"])
    for gi in global_impact[:10]:
        print("  %-22s %-8s %.3f" % (gi["feature"], gi["monitor"], gi["mean_abs_shap"]))
    if schema != "1.0.0":
        print("SHAP share by monitor: network %.0f%%, syscall %.0f%%, energy %.0f%%" % (
            100 * share["network"], 100 * share["syscall"], 100 * share["energy"]))
        for m in ("syscall", "energy"):
            n_m = sum(monitor_of(f) == m for f in order)
            if len(dead[m]) == n_m:
                print("[!] every %s feature is constant in this dataset: that monitor recorded nothing" % m)
    print("\nsaved %s/{xgboost.json, incremental.joblib, config.json, model_card.json}, %s/window_scores.csv" % (
        a.model_dir, a.report_dir))

    if not a.no_plots:
        try:
            from plots import make_plots
            make_plots(ids, lab, attack, pf, tm.cfg, res.get(MAIN), global_impact, a.report_dir)
            print("saved figures in %s/" % a.report_dir)
        except ImportError as e:
            print("(plots skipped: %s)" % e)


if __name__ == "__main__":
    main()
