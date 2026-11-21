#!/usr/bin/env python3 -I
"""run_phase2c.py — the pre-declared improvements in experiments/PHASE2C_PREREG.md.

  python3 -I experiments/run_phase2c.py all            # A (50 outer splits), B and C (100)
  python3 -I experiments/run_phase2c.py nested temporal aetrigger --n-outer 50 --n 100

Reports in reports/phase2c/. Outer test parts are never used for any choice.
"""
import argparse
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core as C  # noqa: E402
from core import (ATTACKS, Data, DETECTORS, grouped_split, primary_split, metrics, summarize, sub, wilson)  # noqa: E402
from common import FEATURE_ORDER_V1, SYSCALL_FEATURES, FEATURE_ORDER_V2  # noqa: E402
from threat_model_v3 import HybridModel  # noqa: E402
import run_phase2b as P2B  # noqa: E402

OUT = os.path.join(C.ROOT, "reports", "phase2c")
HEADER = ["**Status**: PRELIMINARY — attacks from one session (Oct 16). Rules fixed in advance in "
          "`experiments/PHASE2C_PREREG.md` (committed before this run). Outer test parts never used for choices.", ""]
PAPER = "paper: fused XGB+SGD (aug)"
MODELS = [PAPER, "fused XGB+SGD (no aug)", "Random forest", "Logistic regression"]
FEATS = {"all 45": FEATURE_ORDER_V2, "network 28": FEATURE_ORDER_V1, "network+syscall 39": FEATURE_ORDER_V1 + SYSCALL_FEATURES}
FEAT_RANK = {"network 28": 0, "network+syscall 39": 1, "all 45": 2}         # simpler first, for ties


# ------------------------------------------------------------------ generic fit/score on any columns
def fit_score(det, Xtr, ytr, ctr, Xte, names):
    score = det.fit(Xtr, ytr, ctr, list(names))
    s = score(Xte)
    return s, s >= det.thr


def evaluate(det, d, tr, te, X, names):
    s, pred = fit_score(det, X[tr], d.y[tr], d.c[tr], X[te], names)
    return metrics(d.y[te], pred, s, d.r[te], d.c[te])


# ------------------------------------------------------------------ A: nested selection
def exp_nested(d, n_outer, n_inner=4):
    cands = [(m, f) for m in MODELS for f in FEATS]
    picks, sel_ms, paper_ms = Counter(), [], []
    for s in range(n_outer):
        tr, te = grouped_split(d, s)
        dtr = sub(d, tr)
        inner = defaultdict(list)
        for k in range(n_inner):
            itr, ite = grouped_split(dtr, 1000 + 10 * s + k)
            for m, f in cands:
                ix = C.cols(FEATS[f])
                mm = evaluate(DETECTORS[m], dtr, itr, ite, dtr.X[:, ix], FEATS[f])
                inner[(m, f)].append((mm["f1"], mm["fpr"]))
        best = max(cands, key=lambda c: (np.mean([a for a, _ in inner[c]]), -np.mean([b for _, b in inner[c]]), -FEAT_RANK[c[1]]))
        picks[best] += 1
        m, f = best
        ix = C.cols(FEATS[f])
        sel_ms.append(evaluate(DETECTORS[m], d, tr, te, d.X[:, ix], FEATS[f]))
        paper_ms.append(evaluate(DETECTORS[PAPER], d, tr, te, d.X, FEATURE_ORDER_V2))
        print("  outer %d: picked %s / %s" % (s, m, f), flush=True)
    res = {"n_outer": n_outer, "n_inner": n_inner, "picks": {"%s | %s" % k: v for k, v in picks.items()},
           "selected": _dist(sel_ms), "paper": _dist(paper_ms)}
    d_f1 = np.array([a["f1"] for a in sel_ms]) - np.array([b["f1"] for b in paper_ms])
    d_fpr = np.array([a["fpr"] for a in sel_ms]) - np.array([b["fpr"] for b in paper_ms])
    res["paired"] = {"dF1_mean": float(d_f1.mean()), "selected_better": float((d_f1 > 0).mean()),
                     "selected_worse": float((d_f1 < 0).mean()), "dFPR_mean": float(d_fpr.mean())}
    md = ["# Phase 2c A — Pipeline chosen by nested grouped evaluation", ""] + HEADER + [
        "12 candidates (4 models × 3 feature sets). In each of %d outer grouped run-ID splits, the candidate with the "
        "highest mean F1 over %d inner grouped splits **of the outer training part** is refitted on it and scored once on "
        "the outer test part." % (n_outer, n_inner), "",
        "## Outer results (same splits)", "",
        "| Pipeline | F1 mean ± sd [2.5, 97.5] | Recall | FPR | beacon recall | scan recall |", "|---|---|---|---|---|---|",
        _row("selected by nested evaluation", res["selected"]), _row("paper model (all 45)", res["paper"]), "",
        "Paired (same outer splits): mean ΔF1 %+.3f; selected better in %.0f%%, worse in %.0f%% of splits; mean ΔFPR %+.3f." % (
            res["paired"]["dF1_mean"], 100 * res["paired"]["selected_better"], 100 * res["paired"]["selected_worse"],
            res["paired"]["dFPR_mean"]), "",
        "## How often each candidate was selected", "", "| Model | Features | times |", "|---|---|---|"]
    for (m, f), v in picks.most_common():
        md.append("| %s | %s | %d |" % (m, f, v))
    md += ["", "Allowed claim: *a pipeline chosen this way* reaches the outer numbers above on held-out runs. The "
           "selection frequency shows how stable the choice is; it is not a ranking of candidates."]
    write("A_nested_selection", md, res)
    return res


def _dist(ms):
    out = {k: summarize([m[k] for m in ms]) for k in ("f1", "recall", "fpr")}
    for a in ATTACKS:
        out["recall_" + a] = summarize([m["recall_by_class"][a]["recall"] for m in ms if a in m["recall_by_class"]])
    return out


def _row(name, s):
    f = s["f1"]
    return "| %s | %.3f ± %.3f [%.3f, %.3f] | %.3f ± %.3f | %.3f ± %.3f | %.3f | %.3f |" % (
        name, f["mean"], f["std"], f["p2.5"], f["p97.5"], s["recall"]["mean"], s["recall"]["std"],
        s["fpr"]["mean"], s["fpr"]["std"], s["recall_beacon"]["mean"], s["recall_scan"]["mean"])


# ------------------------------------------------------------------ B: temporal features
TEMP_BASE = ["n_http", "pkt_count", "n_unique_dst_ports", "frac_syn"]
TEMP_NAMES = ["%s_%s6" % (f, a) for f in TEMP_BASE for a in ("mean", "max")] + ["http_active_frac_12", "http_gap_std_12"]


def temporal_matrix(rows, gap_reset=30.0):
    """Causal rolling features for every row (rows in any order; computed in start-time order)."""
    order = sorted(range(len(rows)), key=lambda i: rows[i]["window_start_epoch"])
    out = np.zeros((len(rows), len(TEMP_NAMES)))
    hist = []
    prev_end = None
    for i in order:
        r = rows[i]
        if prev_end is not None and r["window_start_epoch"] - prev_end > gap_reset:
            hist = []                                               # recorder gap / new session
        prev_end = r["window_end_epoch"]
        hist.append(r["features"])
        h6, h12 = hist[-6:], hist[-12:]
        vals = []
        for f in TEMP_BASE:
            v = [float(x[f]) for x in h6]
            vals += [float(np.mean(v)), float(np.max(v))]
        act = [j for j, x in enumerate(h12) if float(x["n_http"]) > 0]
        vals.append(len(act) / len(h12))
        gaps = np.diff(act)
        vals.append(float(np.std(gaps)) if len(act) >= 3 else 0.0)
        out[i] = vals
    return out


def supervised_temporal():
    rows = [json.loads(l) for l in open(C.DATA_V3) if l.strip()]
    T = temporal_matrix(rows)
    sup = [i for i, r in enumerate(rows) if r.get("label") in ("benign", "malware")]
    return T[sup]


def exp_temporal(d, n):
    T = supervised_temporal()
    assert len(T) == len(d.y)
    variants = {
        "all 45": (d.X, list(FEATURE_ORDER_V2)),
        "all 45 + temporal (55)": (np.hstack([d.X, T]), list(FEATURE_ORDER_V2) + TEMP_NAMES),
        "network 28": (d.X[:, C.cols(FEATURE_ORDER_V1)], list(FEATURE_ORDER_V1)),
        "network 28 + temporal (38)": (np.hstack([d.X[:, C.cols(FEATURE_ORDER_V1)], T]), list(FEATURE_ORDER_V1) + TEMP_NAMES),
    }
    reps = {k: [] for k in variants}
    for s in range(n):
        tr, te = grouped_split(d, s)
        for k, (X, names) in variants.items():
            reps[k].append(evaluate(DETECTORS[PAPER], d, tr, te, X, names))
    res = {k: _dist(v) for k, v in reps.items()}
    md = ["# Phase 2c B — Cross-window (temporal) features, declared variant", ""] + HEADER + [
        "Paper detector (fused XGB+SGD with scan augmentation, threshold 0.35) on %d grouped run-ID splits, with and "
        "without 10 causal rolling features (see the pre-registration). History resets after a recording gap > 30 s." % n, "",
        "| Features | F1 mean ± sd [2.5, 97.5] | Recall | FPR | beacon recall | scan recall |", "|---|---|---|---|---|---|"]
    for k in variants:
        md.append(_row(k, res[k]))
    for base, plus in (("all 45", "all 45 + temporal (55)"), ("network 28", "network 28 + temporal (38)")):
        df = np.array([m["f1"] for m in reps[plus]]) - np.array([m["f1"] for m in reps[base]])
        bb = [(a["recall_by_class"].get("beacon", {}).get("recall"), b["recall_by_class"].get("beacon", {}).get("recall"))
              for a, b in zip(reps[plus], reps[base])]
        db = np.array([x - y for x, y in bb if x is not None and y is not None])
        res.setdefault("paired", {})[plus] = {"dF1": float(df.mean()), "better": float((df > 0).mean()),
                                              "worse": float((df < 0).mean()), "d_beacon_recall": float(db.mean())}
        md.append("")
        md.append("Paired, %s vs %s: mean ΔF1 %+.3f (better in %.0f%%, worse in %.0f%% of splits); mean Δ beacon recall %+.3f." % (
            plus, base, df.mean(), 100 * (df > 0).mean(), 100 * (df < 0).mean(), db.mean()))
    md += ["", "Caveat: only 3 beacon runs exist, all from Oct 16; every split tests on one of them. Rolling windows "
           "near a run boundary include the previous run's traffic, exactly as a live detector would see it."]
    write("B_temporal_features", md, res)
    return res


# ------------------------------------------------------------------ C: anomaly as an independent trigger
def exp_aetrigger(d, n):
    def rules(hm, X):
        conf, anom, sev = P2B.risk_parts(hm, X)
        risk = P2B.blended(conf, anom, sev)
        return {"risk ≥ 30 (deployed)": risk >= 30, "risk ≥ 30 OR anomaly ≥ 1": (risk >= 30) | (anom >= 1.0)}
    acc = defaultdict(list)
    for s in range(n):
        tr, te = grouped_split(d, s)
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        for k, pred in rules(hm, d.X[te]).items():
            acc[k].append(metrics(d.y[te], pred, runs=d.r[te], cls=d.c[te]))
    tr0, te0 = primary_split(d)
    btest = te0[d.y[te0] == 0]
    loco = {}
    for cl in ATTACKS:
        tr = np.array([i for i in tr0 if d.c[i] != cl]); te = np.r_[np.where(d.c == cl)[0], btest]
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        loco[cl] = {k: metrics(d.y[te], p, runs=d.r[te]) for k, p in rules(hm, d.X[te]).items()}
    res = {"repeated": {k: {"recall": summarize([m["recall"] for m in v]), "fpr": summarize([m["fpr"] for m in v]),
                            "episodes": sum(m["episodes_detected"] for m in v) / sum(m["episodes"] for m in v),
                            "beacon": summarize([m["recall_by_class"]["beacon"]["recall"] for m in v if "beacon" in m["recall_by_class"]])}
                        for k, v in acc.items()},
           "loco": loco}
    md = ["# Phase 2c C — Anomaly score as an independent trigger", ""] + HEADER + [
        "Deployed: act (rate-limit) when risk ≥ 30; the anomaly term alone can add at most 20, so it can never trigger. "
        "Variant: act when risk ≥ 30 OR anomaly ≥ 1.0 (reconstruction error above the 99th percentile of benign training "
        "windows).", "", "## Repeated grouped splits (n = %d), action level" % n, "",
        "| Rule | recall | FPR | episodes acted on | beacon recall |", "|---|---|---|---|---|"]
    for k, v in res["repeated"].items():
        md.append("| %s | %.3f ± %.3f | %.3f ± %.3f | %.3f | %.3f |" % (k, v["recall"]["mean"], v["recall"]["std"],
                  v["fpr"]["mean"], v["fpr"]["std"], v["episodes"], v["beacon"]["mean"]))
    md += ["", "## Unseen attack class (class removed from training; primary split)", "",
           "| Unseen class | deployed: recall / FPR / episodes | OR anomaly: recall / FPR / episodes |", "|---|---|---|"]
    for cl in ATTACKS:
        a, b = loco[cl]["risk ≥ 30 (deployed)"], loco[cl]["risk ≥ 30 OR anomaly ≥ 1"]
        md.append("| %s | %.3f / %.3f / %d of %d | %.3f / %.3f / %d of %d |" % (
            cl, a["recall"], a["fpr"], a["episodes_detected"], a["episodes"], b["recall"], b["fpr"], b["episodes_detected"], b["episodes"]))
    write("C_anomaly_trigger", md, res)
    return res


def write(name, md, obj=None):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name + ".md"), "w") as f:
        f.write("\n".join(md) + "\n")
    if obj is not None:
        with open(os.path.join(OUT, name + ".json"), "w") as f:
            json.dump(obj, f, indent=2, default=lambda o: o.tolist() if hasattr(o, "tolist") else
                      (None if isinstance(o, float) and math.isnan(o) else str(o)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="+")
    ap.add_argument("--n-outer", type=int, default=50)
    ap.add_argument("--n", type=int, default=100)
    a = ap.parse_args()
    which = ["nested", "temporal", "aetrigger"] if "all" in a.which else a.which
    d = C.load_v3()
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "n_outer": a.n_outer, "n": a.n, "which": which}
    for w in which:
        t = time.time()
        {"nested": lambda: exp_nested(d, a.n_outer), "temporal": lambda: exp_temporal(d, a.n),
         "aetrigger": lambda: exp_aetrigger(d, a.n)}[w]()
        print("[%s] done in %.0f s" % (w, time.time() - t), flush=True)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "run_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)


if __name__ == "__main__":
    main()
