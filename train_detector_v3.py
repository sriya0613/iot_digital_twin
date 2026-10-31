#!/usr/bin/env python3
"""train_detector_v3.py — train and evaluate the final hybrid, multi-class detector.

    python3 train_detector_v3.py --dataset data/dataset_v3.jsonl --model-dir models_v3 --report-dir reports_v3

Reads the schema-2.0.0 dataset (with `attack_class`), trains the hybrid model
(threat_model_v3.HybridModel), and writes:
    models_v3/     xgboost.json, incremental.joblib, config.json, autoencoder.joblib,
                   multiclass.json, multiclass_classes.json, model_card.json
    reports_v3/    evaluation.md, confusion_matrix.csv, per_class_metrics.csv
Evaluation: held-out split (last 30% of each class), binary detection + false-positive rate,
per-class precision/recall/F1, confusion matrix, and SHAP contribution by monitor.
"""
import argparse
import json
import os
import shutil
import numpy as np

from common import FEATURE_ORDER_V2, monitor_of
from threat_model_v3 import HybridModel, ATTACK_CLASSES, HAVE_RIVER

NORMAL = {"benign", "unlabeled", "healing"}   # healing/unlabeled windows are treated as normal


def load(path):
    X, ybin, cls = [], [], []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        f = r["features"]
        X.append([f[k] for k in FEATURE_ORDER_V2])
        c = r.get("attack_class") or ""
        is_atk = (r.get("label") == "malware") or (c in ATTACK_CLASSES)
        ybin.append(1 if is_atk else 0)
        cls.append(c if is_atk else "benign")
    return np.array(X, float), np.array(ybin, int), np.array(cls, dtype=object)


def split(cls, frac=0.3, seed=0):
    """Last `frac` of each class -> test (deterministic, no leakage within a class)."""
    rng = np.random.RandomState(seed)
    tr, te = [], []
    for c in set(cls):
        idx = np.where(cls == c)[0]
        rng.shuffle(idx)
        k = int(len(idx) * (1 - frac))
        tr += list(idx[:k]); te += list(idx[k:])
    return np.array(sorted(tr)), np.array(sorted(te))


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset_v3.jsonl")
    ap.add_argument("--model-dir", default="models_v3")
    ap.add_argument("--report-dir", default="reports_v3")
    ap.add_argument("--scaler", default="data/scaler_v3.json", help="scaler used to build the dataset; copied into the model dir so the live loop normalises the same way")
    ap.add_argument("--test-frac", type=float, default=0.3)
    a = ap.parse_args()
    os.makedirs(a.report_dir, exist_ok=True)

    X, ybin, cls = load(a.dataset)
    print("[+] %d windows | %d attack, %d normal | classes: %s"
          % (len(X), ybin.sum(), (1 - ybin).sum(),
             {c: int((cls == c).sum()) for c in sorted(set(cls))}))

    tr, te = split(cls, a.test_frac)
    # ---- train on the training split, evaluate on the held-out split ----
    ev = HybridModel(feature_order=FEATURE_ORDER_V2).fit(X[tr], ybin[tr], cls[tr])

    # binary detection on the held-out set
    p = np.array([ev.core.assess(x, explain=False)["threat_probability"] for x in X[te]])
    pred_atk = p >= ev.core.cfg["t_malicious"]
    tp = int((pred_atk & (ybin[te] == 1)).sum()); fp = int((pred_atk & (ybin[te] == 0)).sum())
    fn = int((~pred_atk & (ybin[te] == 1)).sum()); tn = int((~pred_atk & (ybin[te] == 0)).sum())
    bp, br, bf = prf(tp, fp, fn)
    fpr = fp / (fp + tn) if fp + tn else 0.0

    # multi-class on the held-out attack windows
    atk_te = te[ybin[te] == 1]
    rows = []
    cm = {c: {d: 0 for d in ev.mc_classes} for c in ev.mc_classes}
    for i in atk_te:
        true = cls[i]; predc, _ = ev.predict_class(X[i])
        if true in cm and predc in cm[true]:
            cm[true][predc] += 1
    per_class = {}
    for c in ev.mc_classes:
        tpc = cm[c][c]
        fpc = sum(cm[d][c] for d in ev.mc_classes if d != c)
        fnc = sum(cm[c][d] for d in ev.mc_classes if d != c)
        per_class[c] = prf(tpc, fpc, fnc)

    # SHAP contribution share by monitor (on held-out attack windows)
    shares = {"network": 0.0, "syscall": 0.0, "energy": 0.0}
    for i in atk_te:
        sv, _ = ev.core.shap_values([X[i]]); sv = np.abs(sv[0])
        tot = sv.sum() or 1.0
        for j, fname in enumerate(FEATURE_ORDER_V2):
            shares[monitor_of(fname)] += sv[j] / tot
    nsh = sum(shares.values()) or 1.0
    shares = {k: round(float(v) / nsh, 4) for k, v in shares.items()}

    # ---- retrain on ALL data for the saved model ----
    full = HybridModel(feature_order=FEATURE_ORDER_V2).fit(X, ybin, cls)
    full.save(a.model_dir)
    if os.path.exists(a.scaler):                       # self-contained: live loop reads this
        shutil.copy(a.scaler, os.path.join(a.model_dir, "scaler.json"))

    # ---- write reports ----
    card = {
        "schema_version": "2.0.0", "n_features": len(FEATURE_ORDER_V2), "n_windows": len(X),
        "n_attack": int(ybin.sum()), "n_normal": int((1 - ybin).sum()),
        "class_counts": {c: int((cls == c).sum()) for c in sorted(set(cls))},
        "models": {"binary": "XGBoost + SGD (fused 0.6/0.4)", "anomaly": "MLP autoencoder (benign-only)",
                   "multiclass": "XGBoost multi:softprob", "incremental": "River ARF" if HAVE_RIVER else "SGD (River not installed)"},
        "risk_score": "blended: 0.5*confidence + 0.2*anomaly + 0.3*severity*confidence (0-100)",
        "held_out_binary": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                            "precision": round(bp, 4), "recall": round(br, 4), "f1": round(bf, 4),
                            "false_positive_rate": round(fpr, 4)},
        "held_out_per_class": {c: {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}
                               for c, (p, r, f) in per_class.items()},
        "shap_share_by_monitor": shares,
    }
    json.dump(card, open(os.path.join(a.model_dir, "model_card.json"), "w"), indent=2, default=float)

    with open(os.path.join(a.report_dir, "per_class_metrics.csv"), "w") as f:
        f.write("class,precision,recall,f1\n")
        for c, (p_, r_, f_) in per_class.items():
            f.write("%s,%.4f,%.4f,%.4f\n" % (c, p_, r_, f_))
    with open(os.path.join(a.report_dir, "confusion_matrix.csv"), "w") as f:
        f.write("true\\pred," + ",".join(ev.mc_classes) + "\n")
        for c in ev.mc_classes:
            f.write(c + "," + ",".join(str(cm[c][d]) for d in ev.mc_classes) + "\n")
    with open(os.path.join(a.report_dir, "evaluation.md"), "w") as f:
        f.write("# Hybrid multi-class detector — evaluation\n\n")
        f.write("Held-out = last %d%% of each class.\n\n" % int(a.test_frac * 100))
        f.write("## Binary detection (attack vs normal)\n")
        f.write("precision %.3f | recall %.3f | F1 %.3f | false-positive rate %.3f (fp=%d of %d normal)\n\n"
                % (bp, br, bf, fpr, fp, fp + tn))
        f.write("## Per-class (attack type)\n\n| class | precision | recall | F1 |\n|---|---|---|---|\n")
        for c, (p_, r_, f_) in per_class.items():
            f.write("| %s | %.3f | %.3f | %.3f |\n" % (c, p_, r_, f_))
        f.write("\n## SHAP contribution by monitor (held-out attacks)\n")
        f.write("network %.1f%% | syscall %.1f%% | energy %.1f%%\n"
                % (shares["network"] * 100, shares["syscall"] * 100, shares["energy"] * 100))

    print("[+] binary: P %.3f R %.3f F1 %.3f | FP rate %.3f" % (bp, br, bf, fpr))
    print("[+] per-class F1: %s" % {c: round(f, 3) for c, (_, _, f) in per_class.items()})
    print("[+] SHAP by monitor: %s" % {k: round(float(v),4) for k,v in shares.items()})
    print("[+] saved model -> %s, reports -> %s" % (a.model_dir, a.report_dir))


if __name__ == "__main__":
    main()
