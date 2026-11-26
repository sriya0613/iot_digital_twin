#!/usr/bin/env python3 -I
"""run_phase2d.py — reviewer-driven offline re-analysis (Priority 2). Reports in reports/phase2d/.

  python3 -I experiments/run_phase2d.py all [--n 100] [--n-outer 50]
  python3 -I experiments/run_phase2d.py metrics equalfpr nested thresholds

What changes against Phases 2-2c:
  * Scaling inside each split (review E8). dataset_v3 stores features already min-max scaled with bounds
    fitted on ALL recorded windows (data/scaler_v3.json). Those bounds never clip the stored data, so the raw
    values are recovered exactly as x * (M - m) + m. In every split the bounds are then refitted on the
    TRAINING windows only, applied to the test windows and clipped to [0, 1], as the live detector would.
  metrics     E2/E3/E7: trivial baselines; MCC, balanced accuracy, PR-AUC, ROC-AUC; FPR median and false
              actions per hour; old (global) vs new (in-split) scaling for the deployed recipe.
  equalfpr    E3: recall at equal FPR (0.05, 0.10) read off each split's test ROC (analysis only, not a
              deployable threshold) + paired Wilcoxon tests against the deployed recipe.
  nested      E4/E5: feature set and model chosen on training runs only (nested), with in-split scaling.
  thresholds  F5: share of windows and of runs per class that reach each policy action, for theta in
              {50, 60, 70, 80}, using the full HybridModel risk score.
Status: PRELIMINARY — attacks from one session (Oct 16). Nothing copied from the paper.
"""
import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict

import numpy as np
from scipy.stats import wilcoxon
from sklearn.metrics import roc_curve, average_precision_score, roc_auc_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core as C  # noqa: E402
from core import ATTACKS, Data, grouped_split, summarize, wilson  # noqa: E402
from common import FEATURE_ORDER_V2, FEATURE_ORDER_V1, SYSCALL_FEATURES  # noqa: E402
from threat_model_v3 import HybridModel  # noqa: E402
import run_phase2b as P2B  # noqa: E402

OUT = os.path.join(C.ROOT, "reports", "phase2d")
SCALER = os.path.join(C.ROOT, "data", "scaler_v3.json")
HEADER = ["**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by "
          "`experiments/run_phase2d.py` with **min-max bounds refitted on the training runs of every split**.", ""]
WIN_PER_HOUR = 3600 / 5.0
PAPER = "paper: fused XGB+SGD (aug)"
FEATS = {"all 45": FEATURE_ORDER_V2, "network 28": FEATURE_ORDER_V1,
         "network+syscall 39": FEATURE_ORDER_V1 + SYSCALL_FEATURES}
FEAT_RANK = {"network 28": 0, "network+syscall 39": 1, "all 45": 2}


# ------------------------------------------------------------------ in-split scaling
def raw_from_global(X):
    rng = json.load(open(SCALER))["ranges"]
    lo = np.array([rng[k][0] for k in FEATURE_ORDER_V2], float)
    hi = np.array([rng[k][1] for k in FEATURE_ORDER_V2], float)
    return X * (hi - lo) + lo


def rescale(raw, tr):
    lo, hi = raw[tr].min(axis=0), raw[tr].max(axis=0)
    span = np.where(hi > lo, hi - lo, 1.0)
    Z = np.clip((raw - lo) / span, 0.0, 1.0)
    Z[:, hi <= lo] = 0.0
    return Z


# ------------------------------------------------------------------ metrics
def mcc(tp, fp, fn, tn):
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / den if den else 0.0


def full_metrics(y, s, thr, c):
    y = np.asarray(y); pred = np.asarray(s) >= thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    rec = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn); prec = tp / max(1, tp + fp)
    f1 = 2 * prec * rec / (prec + rec) if tp else 0.0
    m = {"f1": f1, "recall": rec, "fpr": fpr, "precision": prec, "mcc": mcc(tp, fp, fn, tn),
         "bal_acc": 0.5 * (rec + 1 - fpr)}
    s = np.nan_to_num(np.asarray(s, float))
    if len(set(s)) > 1:
        m["pr_auc"] = float(average_precision_score(y, s)); m["roc_auc"] = float(roc_auc_score(y, s))
        fp_r, tp_r, _ = roc_curve(y, s)
        for f in (0.05, 0.10):
            m["recall@fpr%.2f" % f] = float(np.max(tp_r[fp_r <= f])) if (fp_r <= f).any() else 0.0
    else:                                         # constant score (trivial rules): no ranking
        m["pr_auc"] = float(y.mean()); m["roc_auc"] = 0.5
        m["recall@fpr0.05"] = m["recall@fpr0.10"] = 0.0
    for a in ATTACKS:
        k = np.asarray(c) == a
        if k.any():
            m["recall_" + a] = float(pred[k].mean())
    return m


def det_fit_score(name, Xtr, ytr, ctr, Xte, names):
    det = C.DETECTORS[name] if name in C.DETECTORS else KITNET
    score = det.fit(Xtr, ytr, ctr, list(names))
    return score(Xte), det.thr


KITNET = C.Det("kitnet", P2B._kitnet_fit, 1.0, "unsupervised")
ROWS = [  # label, detector, feature set
    ("Deployed recipe (XGB+SGD, aug, 45)", PAPER, "all 45"),
    ("Deployed recipe, network 28", PAPER, "network 28"),
    ("XGB+SGD without scan augmentation (45)", "fused XGB+SGD (no aug)", "all 45"),
    ("XGB+SGD without augmentation, network 28", "fused XGB+SGD (no aug)", "network 28"),
    ("Random forest (45)", "Random forest", "all 45"),
    ("Logistic regression (45)", "Logistic regression", "all 45"),
    ("Autoencoder, benign only (45)", "Autoencoder (benign-only)", "all 45"),
    ("KitNET-style, benign only (45)", "kitnet", "all 45"),
]


def _agg(ms):
    keys = sorted({k for m in ms for k in m})
    return {k: summarize([m[k] for m in ms if k in m]) for k in keys}


def exp_metrics(d, raw, n):
    per = defaultdict(list)
    old = []
    for s in range(n):
        tr, te = grouped_split(d, s)
        Z = rescale(raw, tr)
        for lab, det, fs in ROWS:
            ix = C.cols(FEATS[fs])
            sc, thr = det_fit_score(det, Z[tr][:, ix], d.y[tr], d.c[tr], Z[te][:, ix], FEATS[fs])
            per[lab].append(full_metrics(d.y[te], sc, thr, d.c[te]))
        yt = d.y[te]
        per["Trivial: flag every window"].append(full_metrics(yt, np.ones(len(yt)), 0.5, d.c[te]))
        rnd = np.random.RandomState(s).rand(len(yt))
        per["Trivial: random at training attack rate"].append(
            full_metrics(yt, rnd, 1 - d.y[tr].mean(), d.c[te]))
        sc, thr = det_fit_score(PAPER, d.X[tr], d.y[tr], d.c[tr], d.X[te], FEATURE_ORDER_V2)
        old.append(full_metrics(d.y[te], sc, thr, d.c[te]))
        print("  metrics split %d" % s, flush=True)
    agg = {k: _agg(v) for k, v in per.items()}
    agg["Deployed recipe, OLD global scaling (45)"] = _agg(old)
    # paired tests vs deployed recipe
    base = per[ROWS[0][0]]
    tests = {}
    for lab in per:
        if lab == ROWS[0][0]:
            continue
        for k in ("f1", "mcc", "pr_auc", "recall@fpr0.05", "recall@fpr0.10"):
            a = np.array([m[k] for m in per[lab]]); b = np.array([m[k] for m in base])
            dlt = a - b
            p = float(wilcoxon(a, b).pvalue) if np.any(dlt != 0) else 1.0
            tests.setdefault(lab, {})[k] = {"mean_delta": float(dlt.mean()), "better": float((dlt > 0).mean()),
                                            "worse": float((dlt < 0).mean()), "p": p}
    fprs = np.array([m["fpr"] for m in base])
    res = {"n": n, "rows": agg, "paired_vs_deployed": tests,
           "deployed_fpr": {"median": float(np.median(fprs)), "mean": float(fprs.mean()),
                            "p90": float(np.percentile(fprs, 90)), "share_zero": float((fprs == 0).mean()),
                            "false_alerts_per_hour_median": float(np.median(fprs) * WIN_PER_HOUR),
                            "false_alerts_per_hour_mean": float(fprs.mean() * WIN_PER_HOUR)}}
    write_metrics(res)
    return res


def _m(a, k):
    return "%.3f" % a[k]["mean"] if k in a else "–"


def write_metrics(res):
    md = ["# Phase 2d — Metrics with in-split scaling, trivial baselines and equal-FPR comparison", ""] + HEADER + [
        "%d grouped run-ID splits (same seeds as Phases 2-2c). Mean over splits; sd and percentiles in the JSON. "
        "Recall@FPR is read off each split's test ROC curve: it compares ranking quality at equal false-alarm "
        "rates and is **not** a threshold the live system could use." % res["n"], "",
        "| Detector | F1 | Recall | FPR | MCC | Bal. acc. | PR-AUC | ROC-AUC | Recall@FPR 0.05 | Recall@FPR 0.10 | scan | beacon |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    order = [r[0] for r in ROWS] + ["Deployed recipe, OLD global scaling (45)", "Trivial: flag every window",
                                     "Trivial: random at training attack rate"]
    for lab in order:
        a = res["rows"][lab]
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            lab, _m(a, "f1"), _m(a, "recall"), _m(a, "fpr"), _m(a, "mcc"), _m(a, "bal_acc"), _m(a, "pr_auc"),
            _m(a, "roc_auc"), _m(a, "recall@fpr0.05"), _m(a, "recall@fpr0.10"), _m(a, "recall_scan"),
            _m(a, "recall_beacon")))
    f = res["deployed_fpr"]
    md += ["", "## Deployed recipe: false-positive rate across splits", "",
           "median %.3f, mean %.3f, 90th percentile %.3f; FPR = 0 in %.0f%% of splits. At one window every 5 s this is "
           "a median of %.0f (mean %.0f) benign windows per hour flagged as malicious." % (
               f["median"], f["mean"], f["p90"], 100 * f["share_zero"], f["false_alerts_per_hour_median"],
               f["false_alerts_per_hour_mean"]), "",
           "## Paired comparison with the deployed recipe (same splits, Wilcoxon signed-rank)", "",
           "| Detector | ΔMCC (p) | ΔPR-AUC (p) | ΔRecall@FPR 0.05 (p) | ΔRecall@FPR 0.10 (p) | better/worse in PR-AUC |",
           "|---|---|---|---|---|---|"]
    for lab, t in res["paired_vs_deployed"].items():
        if lab.startswith("Trivial"):
            continue
        md.append("| %s | %+.3f (%.3g) | %+.3f (%.3g) | %+.3f (%.3g) | %+.3f (%.3g) | %.0f%% / %.0f%% |" % (
            lab, t["mcc"]["mean_delta"], t["mcc"]["p"], t["pr_auc"]["mean_delta"], t["pr_auc"]["p"],
            t["recall@fpr0.05"]["mean_delta"], t["recall@fpr0.05"]["p"], t["recall@fpr0.10"]["mean_delta"],
            t["recall@fpr0.10"]["p"], 100 * t["pr_auc"]["better"], 100 * t["pr_auc"]["worse"]))
    md += ["", "Splits share most training runs, so they are not independent; p-values are descriptive, not a formal "
           "test across sessions."]
    write("A_metrics_insplit_scaling", md, res)


# ------------------------------------------------------------------ nested selection (in-split scaling)
NESTED_MODELS = [PAPER, "fused XGB+SGD (no aug)", "Random forest", "Logistic regression"]


def exp_nested(d, raw, n_outer, n_inner=4):
    cands = [(m, f) for m in NESTED_MODELS for f in FEATS]
    picks, sel, dep = Counter(), [], []
    for s in range(n_outer):
        tr, te = grouped_split(d, s)
        dtr = C.sub(d, tr); rtr = raw[tr]
        inner = defaultdict(list)
        for k in range(n_inner):
            itr, ite = grouped_split(dtr, 1000 + 10 * s + k)
            Zi = rescale(rtr, itr)
            for m, f in cands:
                ix = C.cols(FEATS[f])
                sc, thr = det_fit_score(m, Zi[itr][:, ix], dtr.y[itr], dtr.c[itr], Zi[ite][:, ix], FEATS[f])
                mm = full_metrics(dtr.y[ite], sc, thr, dtr.c[ite])
                inner[(m, f)].append((mm["mcc"], mm["fpr"]))
        best = max(cands, key=lambda c: (np.mean([a for a, _ in inner[c]]), -np.mean([b for _, b in inner[c]]),
                                         -FEAT_RANK[c[1]]))
        picks[best] += 1
        Z = rescale(raw, tr)
        m, f = best; ix = C.cols(FEATS[f])
        sc, thr = det_fit_score(m, Z[tr][:, ix], d.y[tr], d.c[tr], Z[te][:, ix], FEATS[f])
        sel.append(full_metrics(d.y[te], sc, thr, d.c[te]))
        sc, thr = det_fit_score(PAPER, Z[tr], d.y[tr], d.c[tr], Z[te], FEATURE_ORDER_V2)
        dep.append(full_metrics(d.y[te], sc, thr, d.c[te]))
        print("  nested outer %d: %s / %s" % (s, m, f), flush=True)
    a, b = _agg(sel), _agg(dep)
    dm = np.array([x["mcc"] for x in sel]) - np.array([x["mcc"] for x in dep])
    res = {"n_outer": n_outer, "criterion": "inner mean MCC (ties: lower FPR, simpler feature set)",
           "picks": {"%s | %s" % k: v for k, v in picks.items()}, "selected": a, "deployed": b,
           "paired_mcc": {"mean_delta": float(dm.mean()), "better": float((dm > 0).mean()),
                          "worse": float((dm < 0).mean()),
                          "p": float(wilcoxon(dm).pvalue) if np.any(dm != 0) else 1.0}}
    md = ["# Phase 2d — Model and feature set chosen on training runs only (nested, in-split scaling)", ""] + HEADER + [
        "12 candidates (4 models × 3 feature sets). In each of %d outer splits the candidate with the highest mean "
        "**MCC** over %d inner splits of the outer training part (ties: lower FPR, then the simpler feature set) is "
        "refitted and scored once on the outer test part. MCC replaces F1 as the criterion because F1 rewards "
        "flagging everything at this class mix (review E2)." % (n_outer, n_inner), "",
        "| Pipeline | F1 | Recall | FPR | MCC | PR-AUC | scan | beacon |", "|---|---|---|---|---|---|---|---|"]
    for lab, x in (("selected by nested evaluation", a), ("deployed recipe (45)", b)):
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (lab, _m(x, "f1"), _m(x, "recall"), _m(x, "fpr"),
                                                              _m(x, "mcc"), _m(x, "pr_auc"), _m(x, "recall_scan"),
                                                              _m(x, "recall_beacon")))
    p = res["paired_mcc"]
    md += ["", "Paired ΔMCC %+.3f (selected better in %.0f%%, worse in %.0f%% of splits; Wilcoxon p = %.3g)." % (
        p["mean_delta"], 100 * p["better"], 100 * p["worse"], p["p"]), "",
        "| Model | Features | times selected |", "|---|---|---|"]
    for (m, f), v in picks.most_common():
        md.append("| %s | %s | %d |" % (m, f, v))
    write("B_nested_selection_mcc", md, res)
    return res


# ------------------------------------------------------------------ policy actions per class
THETAS = (50, 60, 70, 80)


def exp_thresholds(d, raw, n):
    win = defaultdict(list)             # class -> risk values
    runs = defaultdict(list)            # (class) -> list of per-run max risk
    for s in range(n):
        tr, te = grouped_split(d, s)
        Z = rescale(raw, tr)
        hm = HybridModel().fit(Z[tr], d.y[tr], d.c[tr])
        conf, anom, sev = P2B.risk_parts(hm, Z[te])
        rk = P2B.blended(conf, anom, sev)
        rk0 = P2B.blended(conf, np.zeros_like(anom), sev)    # same windows, anomaly term removed
        for c, r_, r0 in zip(d.c[te], rk, rk0):
            win[c].append((r_, r0))
        for rid in sorted(set(d.r[te])):
            k = d.r[te] == rid
            runs[d.c[te][k][0]].append((int(rk[k].max()), int(rk0[k].max())))
        print("  thresholds split %d" % s, flush=True)
    out = {"n": n, "window": {}, "run": {}}
    for c in ["benign"] + ATTACKS:
        r = np.array([a for a, _ in win[c]]); r0 = np.array([b for _, b in win[c]])
        out["window"][c] = {"n": int(len(r)), "rate_limit_or_more": float((r >= 30).mean()),
                            **{"quarantine_theta%d" % t: float((r > t).mean()) for t in THETAS},
                            "quarantine_theta70_without_anomaly": float((r0 > 70).mean())}
        rr = np.array([a for a, _ in runs[c]]); rr0 = np.array([b for _, b in runs[c]])
        out["run"][c] = {"n_run_tests": int(len(rr)), "any_action": float((rr >= 30).mean()),
                         **{"any_quarantine_theta%d" % t: float((rr > t).mean()) for t in THETAS},
                         "any_quarantine_theta70_without_anomaly": float((rr0 > 70).mean())}
    md = ["# Phase 2d — Policy action per class and threshold sensitivity", ""] + HEADER + [
        "Full HybridModel risk (confidence, anomaly, severity), as in `assess()`, for every held-out window over %d "
        "splits. 'Without anomaly' recomputes the same risk with the anomaly term set to 0, to show how much "
        "quarantine depends on it (review F5)." % n, "",
        "## Share of held-out windows", "",
        "| Class | windows | ≥ 30 (act) | > 50 | > 60 | > 70 (deployed θ) | > 80 | > 70 without anomaly |",
        "|---|---|---|---|---|---|---|---|"]
    for c, v in out["window"].items():
        md.append("| %s | %d | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% |" % (
            c, v["n"], 100 * v["rate_limit_or_more"], 100 * v["quarantine_theta50"], 100 * v["quarantine_theta60"],
            100 * v["quarantine_theta70"], 100 * v["quarantine_theta80"], 100 * v["quarantine_theta70_without_anomaly"]))
    md += ["", "## Share of held-out runs with at least one window in the band (run-level action)", "",
           "| Class | run tests | any action (≥ 30) | any > 50 | any > 60 | any > 70 | any > 80 | any > 70 without anomaly |",
           "|---|---|---|---|---|---|---|---|"]
    for c, v in out["run"].items():
        md.append("| %s | %d | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% |" % (
            c, v["n_run_tests"], 100 * v["any_action"], 100 * v["any_quarantine_theta50"],
            100 * v["any_quarantine_theta60"], 100 * v["any_quarantine_theta70"], 100 * v["any_quarantine_theta80"],
            100 * v["any_quarantine_theta70_without_anomaly"]))
    md += ["", "For benign runs, 'any > θ' is the share of benign runs that would have caused at least one restore."]
    write("C_policy_thresholds", md, out)
    return out


# ------------------------------------------------------------------ io
def write(name, md, obj=None):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name + ".md"), "w") as f:
        f.write("\n".join(md) + "\n")
    if obj is not None:
        with open(os.path.join(OUT, name + ".json"), "w") as f:
            json.dump(obj, f, indent=2, default=lambda o: o.tolist() if hasattr(o, "tolist") else str(o))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="+", choices=["all", "metrics", "nested", "thresholds"])
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--n-outer", type=int, default=50)
    a = ap.parse_args()
    d = C.load_v3()
    raw = raw_from_global(d.X)
    assert np.allclose(rescale(raw, np.arange(len(raw))).max(axis=0)[raw.max(axis=0) > raw.min(axis=0)], 1.0)
    which = ["metrics", "thresholds", "nested"] if "all" in a.which else a.which
    for w in which:
        print("==", w, flush=True)
        {"metrics": lambda: exp_metrics(d, raw, a.n), "nested": lambda: exp_nested(d, raw, a.n_outer),
         "thresholds": lambda: exp_thresholds(d, raw, a.n)}[w]()
    meta = {"scaler": "min-max refitted on training runs of every split", "n": a.n, "n_outer": a.n_outer}
    write("run_meta", ["run_meta"], meta)


if __name__ == "__main__":
    main()
