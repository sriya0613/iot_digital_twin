#!/usr/bin/env python3 -I
"""run_phase2.py — Phase 2 experiments on the EXISTING data (no live twin needed).

  python3 -I experiments/run_phase2.py all          # everything (~10 min on 2 cores)
  python3 -I experiments/run_phase2.py exp3 exp6    # selected experiments
  python3 -I experiments/run_phase2.py all --n 20   # fewer repeated splits (quick check)

Experiments (reports in reports/phase2/):
  exp3  baselines vs the paper's detector          (primary, repeated, Oct 3 cross-session)
  exp4  detector ablation: XGB / SGD / fusion / augmentation / risk blend at policy level
  exp5  monitor ablation: network / +syscall / +energy / syscall+energy / all / non-constant
  exp8  sensitivity: decision threshold, fusion weight, policy risk thresholds
  exp9  feedback loop: unseen attack class, then analyst-confirmed vs self-training updates
  exp10 autoencoder / unknown-threat: leave-one-class-out for supervised core vs autoencoder
  exp6  statistical robustness: training-seed variance, paired comparisons, cross-session

All numbers are measured by this script on dataset_v3 (Oct 16 + Oct 19) and the corrected
Oct 3 reconstruction. Nothing is copied from the paper. Status: PRELIMINARY (one attack session
for training; Oct 3 adds an independent session for scan + benign only).
"""
import argparse
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core as C  # noqa: E402
from core import (DETECTORS, ATTACKS, FEATURE_SETS, Data, sub, run_det, metrics, summarize,  # noqa: E402
                  primary_split, grouped_split, write, fmt_ci, cols, wilson)
import threat_model as tm  # noqa: E402
from threat_model import ThreatModel  # noqa: E402
from threat_model_v3 import HybridModel, SEVERITY, RISK_W  # noqa: E402
from common import FEATURE_ORDER_V2  # noqa: E402

HEADER = ["**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). "
          "Measured by `experiments/run_phase2.py`; nothing copied from the paper.", ""]
PAPER = "paper: fused XGB+SGD (aug)"


def repeated(d, dets, n, names=None):
    """Run each detector over n grouped splits. Returns {det: [metrics...]}."""
    out = {k: [] for k in dets}
    for s in range(n):
        tr, te = grouped_split(d, s)
        for k in dets:
            m, _ = run_det(DETECTORS[k] if isinstance(k, str) and k in DETECTORS else k, sub(d, tr), sub(d, te), names)
            out[k].append(m)
    return out


def rep_row(name, ms):
    f1, r, fpr = summarize([m["f1"] for m in ms]), summarize([m["recall"] for m in ms]), summarize([m["fpr"] for m in ms])
    auc = summarize([m.get("roc_auc") for m in ms])
    ep = sum(m["episodes_detected"] for m in ms) / max(1, sum(m["episodes"] for m in ms))
    return ("| %s | %.3f ± %.3f [%.3f, %.3f] | %.3f ± %.3f | %.3f ± %.3f | %.3f | %.3f |" %
            (name, f1["mean"], f1["std"], f1["p2.5"], f1["p97.5"], r["mean"], r["std"], fpr["mean"], fpr["std"], auc["mean"], ep),
            {"f1": f1, "recall": r, "fpr": fpr, "roc_auc": auc, "episode_detection_rate": ep})


REP_HEAD = ["| Detector | F1 mean ± sd [2.5, 97.5 pct] | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Episodes detected |",
            "|---|---|---|---|---|---|"]


def prim_row(name, m):
    return "| %s | %s | %s | %s | %.3f | %s | %d/%d |" % (
        name, fmt_ci(m, "precision"), fmt_ci(m, "recall"), fmt_ci(m, "fpr"), m["f1"],
        "%.3f" % m["roc_auc"] if "roc_auc" in m else "—", m["episodes_detected"], m["episodes"])


PRIM_HEAD = ["| Detector | Precision [95% CI] | Recall [95% CI] | FPR [95% CI] | F1 | ROC-AUC | Episodes detected |",
             "|---|---|---|---|---|---|---|"]


# ------------------------------------------------------------------ EXP-3
def exp3(d, o3, n):
    tr, te = primary_split(d)
    md = ["# EXP-3: Baselines vs the paper's detector", ""] + HEADER + [
        "Same splits, features (all 45) and train-only fitting for every detector. Decision thresholds are fixed "
        "in advance: 0.35 for the paper's fused score (its deployed value), 0.5 for other classifiers' probabilities, "
        "and the 99th percentile of benign training scores for the two benign-only detectors.", "",
        "## A. Primary run-ID split (Phase 1 split; 127 test windows, 8 test runs)", ""] + PRIM_HEAD
    res = {"primary": {}, "repeated": {}, "oct3": {}}
    for k, det in DETECTORS.items():
        m, _ = run_det(det, sub(d, tr), sub(d, te))
        res["primary"][k] = m
        md.append(prim_row(k, m))
    md.append("")
    md.append("One-rule baseline chose: `%s` %s %.4f (on the training split)." % (
        C._one_rule.last[0], ">=" if C._one_rule.last[2] > 0 else "<=", C._one_rule.last[1]))
    md += ["", "## B. Repeated grouped splits (n = %d)" % n, "",
           "Per class ~30%% of run_ids held out per split. Every split has 1 test episode of beacon and bruteforce "
           "(only 3 and 4 exist), so per-split numbers are noisy; the spread below is the honest uncertainty.", ""] + REP_HEAD
    rep = repeated(d, list(DETECTORS), n)
    for k in DETECTORS:
        row, s = rep_row(k, rep[k]); md.append(row); res["repeated"][k] = s
    # paired comparison against the paper model
    md += ["", "### Paired comparison with the paper model (same splits)", "",
           "| Detector | mean ΔF1 (det − paper) | splits where det F1 > paper | mean ΔFPR |", "|---|---|---|---|"]
    pf = np.array([m["f1"] for m in rep[PAPER]]); pfpr = np.array([m["fpr"] for m in rep[PAPER]])
    res["paired"] = {}
    for k in DETECTORS:
        if k == PAPER:
            continue
        f = np.array([m["f1"] for m in rep[k]]); fp = np.array([m["fpr"] for m in rep[k]])
        win = float((f > pf).mean()); res["paired"][k] = {"dF1": float((f - pf).mean()), "win": win, "dFPR": float((fp - pfpr).mean())}
        md.append("| %s | %+.3f | %.0f%% | %+.3f |" % (k, (f - pf).mean(), 100 * win, (fp - pfpr).mean()))
    # cross-session
    md += ["", "## C. Cross-session: train on Oct 16 + Oct 19, test on Oct 3", "",
           "Oct 3 test set: %d benign windows (1 run), %d scan windows (%d separate nmap runs, `-p 1-1000`, "
           "class inferred from the manifest command). This is the only test data from an independent session." % (
               int((o3.y == 0).sum()), int((o3.y == 1).sum()), len(set(o3.r[o3.y == 1]))), ""] + PRIM_HEAD
    for k, det in DETECTORS.items():
        m, _ = run_det(det, d, o3)
        res["oct3"][k] = m; md.append(prim_row(k, m))
    md += ["", "## Reading", "", interpret3(res)]
    write("EXP-3_baselines", md, res)
    return res


def interpret3(res):
    rep = res["repeated"]
    best = max(rep, key=lambda k: rep[k]["f1"]["mean"])
    p = rep[PAPER]
    return ("Across %d repeated splits the paper detector's mean F1 is %.3f (sd %.3f). The highest mean F1 is "
            "**%s** at %.3f. Differences smaller than about one standard deviation should not be reported as "
            "improvements. These are window-level results on a dataset whose attacks come from one session; "
            "the Oct 3 table is the only cross-session evidence and covers scans only." %
            (p["f1"]["n"], p["f1"]["mean"], p["f1"]["std"], best, rep[best]["f1"]["mean"]))


# ------------------------------------------------------------------ EXP-4
def exp4(d, o3, n):
    keys = [PAPER, "fused XGB+SGD (no aug)", "XGBoost only (aug)", "SGD only (aug)"]
    md = ["# EXP-4: Detector ablation", ""] + HEADER + [
        "## A. Components of the binary core (repeated grouped splits, n = %d)" % n, ""] + REP_HEAD
    rep = repeated(d, keys, n)
    res = {"core": {}}
    for k in keys:
        row, s = rep_row(k, rep[k]); md.append(row); res["core"][k] = s

    # fusion arithmetic: how much can the SGD part alone move the fused score?
    md += ["", "## B. What the 0.6/0.4 fusion at threshold 0.35 implies", "",
           "Fused = 0.6·p_xgb + 0.4·p_sgd ≥ 0.35. If XGBoost gives 0, SGD alone must reach 0.875. "
           "If SGD gives 0, XGBoost alone must reach 0.583. So either model can raise an alert alone only when very confident; "
           "this matters for the feedback loop (EXP-9), which updates only the SGD part.", ""]

    # policy-level: blended risk -> action, and the autoencoder's possible influence
    md += ["## C. Policy level: blended risk score → action (primary split)", "",
           "risk = 100·(0.5·conf + 0.2·anomaly + 0.3·severity·conf); policy acts at risk ≥ 30 (rate-limit) and ≥ 70 (quarantine). "
           "Severity is only applied when the binary label is not benign.", ""]
    tr, te = primary_split(d)
    hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
    rows = []
    for x in d.X[te]:
        a = hm.assess(x, explain=False)
        rows.append((a["risk_score"], a["threat_probability"], a["anomaly_score"], a["attack_class"]))
    risk = np.array([r[0] for r in rows]); conf = np.array([r[1] for r in rows]); anom = np.array([r[2] for r in rows])
    yt = d.y[te]
    no_ae = np.array([int(round(100 * np.clip(0.5 * c_ + 0.3 * SEVERITY.get(ac, 0.0) * c_ if ac else 0.5 * c_, 0, 1)))
                      for c_, (_, _, _, ac) in zip(conf, rows)])
    md += ["| Decision | Recall | FPR | Episodes |", "|---|---|---|---|"]
    res["policy"] = {}
    for name, pred in [("label malicious (fused ≥ 0.35)", conf >= 0.35),
                       ("risk ≥ 30 (any action)", risk >= 30), ("risk ≥ 70 (quarantine)", risk >= 70),
                       ("risk ≥ 30 without anomaly term", no_ae >= 30)]:
        m = metrics(yt, pred, runs=d.r[te]); res["policy"][name] = m
        md.append("| %s | %s | %s | %d/%d |" % (name, fmt_ci(m, "recall"), fmt_ci(m, "fpr"), m["episodes_detected"], m["episodes"]))
    changed = int(((risk >= 30) != (no_ae >= 30)).sum())
    ae_only = int(((anom >= 1.0) & (conf < 0.35) & (yt == 1)).sum())
    md += ["", "- Windows whose action (risk ≥ 30) changes when the anomaly term is removed: **%d of %d**." % (changed, len(te)),
           "- Attack windows the autoencoder flags (anomaly ≥ 1) but the fused score misses: **%d**." % ae_only,
           "- Maximum risk from the anomaly term alone (conf = 0): 0.2 × 100 = **20 < 30**, so by construction the autoencoder "
           "can never trigger a containment action on its own. An attack the supervised core misses entirely "
           "(a true unknown threat) cannot be contained by the current risk formula.", ""]
    res["policy_ae_changed"] = changed; res["ae_only_attack_windows"] = ae_only
    write("EXP-4_detector_ablation", md, res)
    return res


# ------------------------------------------------------------------ EXP-5
def exp5(d, o3, n):
    det = DETECTORS[PAPER]
    md = ["# EXP-5: Monitor (feature-group) ablation", ""] + HEADER + [
        "Paper detector retrained on each feature subset, same splits. Note 8 features are constant in this "
        "dataset (3 network, 5 syscall), so the syscall monitor contributes 6 live features, not 11.", "",
        "## A. Repeated grouped splits (n = %d)" % n, ""] + REP_HEAD
    res = {"repeated": {}, "primary": {}, "oct3": {}}
    reps = {}
    for name, feats in FEATURE_SETS.items():
        ms = []
        for s in range(n):
            tr, te = grouped_split(d, s)
            ms.append(run_det(det, sub(d, tr), sub(d, te), feats)[0])
        reps[name] = ms
        row, st = rep_row(name, ms); md.append(row); res["repeated"][name] = st
    base = np.array([m["f1"] for m in reps["network (28)"]])
    md += ["", "### Paired gain over network-only (same splits)", "", "| Feature set | mean ΔF1 | splits better | splits worse |", "|---|---|---|---|"]
    for name in FEATURE_SETS:
        if name == "network (28)":
            continue
        f = np.array([m["f1"] for m in reps[name]])
        md.append("| %s | %+.3f | %.0f%% | %.0f%% |" % (name, (f - base).mean(), 100 * (f > base).mean(), 100 * (f < base).mean()))
        res.setdefault("paired_vs_network", {})[name] = {"dF1": float((f - base).mean()), "better": float((f > base).mean()), "worse": float((f < base).mean())}
    md += ["", "## B. Primary split", ""] + PRIM_HEAD
    tr, te = primary_split(d)
    for name, feats in FEATURE_SETS.items():
        m, _ = run_det(det, sub(d, tr), sub(d, te), feats); res["primary"][name] = m; md.append(prim_row(name, m))
    md += ["", "## C. Cross-session (Oct 3)", ""] + PRIM_HEAD
    for name, feats in FEATURE_SETS.items():
        m, _ = run_det(det, d, o3, feats); res["oct3"][name] = m; md.append(prim_row(name, m))
    md += ["", "## D. Per-class recall, repeated splits (mean over splits containing the class)", "",
           "| Feature set | " + " | ".join(ATTACKS) + " |", "|---" * (len(ATTACKS) + 1) + "|"]
    for name in FEATURE_SETS:
        vals = []
        for a in ATTACKS:
            v = [m["recall_by_class"][a]["recall"] for m in reps[name] if a in m["recall_by_class"]]
            vals.append("%.3f" % np.mean(v))
        md.append("| %s | %s |" % (name, " | ".join(vals)))
    write("EXP-5_monitor_ablation", md, res)
    return res


# ------------------------------------------------------------------ EXP-8
def exp8(d, o3, n):
    md = ["# EXP-8: Sensitivity analysis", ""] + HEADER + [
        "These sweeps are **descriptive**: they show how results move with each setting. The deployed values "
        "(threshold 0.35, weights 0.6/0.4, actions at risk 30/70) were fixed in the code before this evaluation and are "
        "not re-tuned here, because choosing them on these test splits would leak test information.", ""]
    res = {}
    # threshold sweep on repeated splits: one fit per split, reuse scores
    ths = np.round(np.arange(0.05, 0.96, 0.05), 2)
    ws = np.round(np.arange(0.0, 1.01, 0.1), 1)
    acc_t = {t: [] for t in ths}; acc_w = {w: [] for w in ws}
    for s in range(n):
        tr, te = grouped_split(d, s)
        m = ThreatModel(None, FEATURE_ORDER_V2).fit(d.X[tr], d.y[tr])
        px, pi = m.p_xgb(d.X[te]), m.p_inc(d.X[te]); yt = d.y[te]
        fused = 0.6 * px + 0.4 * pi
        for t in ths:
            acc_t[t].append(metrics(yt, fused >= t))
        for w in ws:
            acc_w[w].append(metrics(yt, (w * px + (1 - w) * pi) >= 0.35, w * px + (1 - w) * pi))
    md += ["## A. Decision threshold on the fused score (weights 0.6/0.4), n = %d splits" % n, "",
           "| threshold | precision | recall | FPR | F1 |", "|---|---|---|---|---|"]
    res["threshold"] = {}
    for t in ths:
        ms = acc_t[t]
        row = {k: summarize([m[k] for m in ms])["mean"] for k in ("precision", "recall", "fpr", "f1")}
        res["threshold"][float(t)] = row
        mark = " ← deployed" if abs(t - 0.35) < 1e-9 else ""
        md.append("| %.2f%s | %.3f | %.3f | %.3f | %.3f |" % (t, mark, row["precision"], row["recall"], row["fpr"], row["f1"]))
    md += ["", "## B. Fusion weight w_xgb (w_sgd = 1 − w_xgb), threshold 0.35", "",
           "| w_xgb | recall | FPR | F1 | ROC-AUC |", "|---|---|---|---|---|"]
    res["weight"] = {}
    for w in ws:
        ms = acc_w[w]
        row = {k: summarize([m.get(k) for m in ms])["mean"] for k in ("recall", "fpr", "f1", "roc_auc")}
        res["weight"][float(w)] = row
        mark = " ← deployed" if abs(w - 0.6) < 1e-9 else ""
        md.append("| %.1f%s | %.3f | %.3f | %.3f | %.3f |" % (w, mark, row["recall"], row["fpr"], row["f1"], row["roc_auc"]))
    # policy risk thresholds
    md += ["", "## C. Policy action threshold on the blended risk score (primary split)", "",
           "| act when risk ≥ | recall | FPR | episodes detected |", "|---|---|---|---|"]
    tr, te = primary_split(d)
    hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
    risk = np.array([hm.assess(x, explain=False)["risk_score"] for x in d.X[te]])
    res["risk"] = {}
    for t in (10, 20, 30, 40, 50, 60, 70, 80, 90):
        m = metrics(d.y[te], risk >= t, runs=d.r[te]); res["risk"][t] = m
        mark = " ← rate-limit" if t == 30 else " ← quarantine" if t == 70 else ""
        md.append("| %d%s | %s | %s | %d/%d |" % (t, mark, fmt_ci(m, "recall"), fmt_ci(m, "fpr"), m["episodes_detected"], m["episodes"]))
    best_t = max(res["threshold"], key=lambda t: res["threshold"][t]["f1"])
    md += ["", "Highest mean F1 in sweep A is at threshold %.2f (F1 %.3f vs %.3f at 0.35). Treat this as a hypothesis "
           "to confirm on the Phase 4 validation sessions, not as a tuned result." % (best_t, res["threshold"][best_t]["f1"], res["threshold"][0.35]["f1"])]
    write("EXP-8_sensitivity", md, res)
    return res


# ------------------------------------------------------------------ EXP-9
def exp9(d, o3, n):
    md = ["# EXP-9: Feedback loop with an unseen attack class", ""] + HEADER + [
        "Protocol, per attack class C: train the paper's binary core with **every C window removed** (benign and other "
        "classes use the primary split's training runs). C's runs are sorted by time; the first run is the 'feedback' "
        "episode, the rest are the test episodes. Then update the incremental SGD model on the feedback episode, "
        "one window at a time, in two ways:", "",
        "- **confirmed**: analyst-confirmed label 1 for each window (`partial_fit`, what HybridModel.online_update does with a confirmed label);",
        "- **self-training**: the deployed rule `ThreatModel.online_update` (pseudo-label only when fused ≤ 0.05 or ≥ 0.95).", "",
        "XGBoost is never updated (as in the code). Test = remaining C runs + benign test runs of the primary split.", "",
        "| Unseen class | test C windows / runs | recall before | after self-training (updates used) | after confirmed | FPR before | FPR after confirmed |",
        "|---|---|---|---|---|---|---|"]
    res = {}
    tr0, te0 = primary_split(d)
    btest = te0[d.y[te0] == 0]
    for C_ in ATTACKS:
        idxC = np.where(d.c == C_)[0]
        runs = sorted(set(d.r[idxC]))
        fb = idxC[d.r[idxC] == runs[0]]
        tc = idxC[np.isin(d.r[idxC], runs[1:])]
        tr = np.array([i for i in tr0 if d.c[i] != C_])
        te = np.r_[tc, btest]
        out = {}
        for mode in ("self", "confirmed"):
            m = ThreatModel(None, FEATURE_ORDER_V2).fit(d.X[tr], d.y[tr])
            before = metrics(d.y[te], m.threat_probability(d.X[te]) >= 0.35)
            used = 0
            for x in d.X[fb]:
                if mode == "self":
                    used += m.online_update(x, float(m.threat_probability([x])[0])) is not None
                else:
                    m.inc.partial_fit(np.asarray([x]), [1]); used += 1
            after = metrics(d.y[te], m.threat_probability(d.X[te]) >= 0.35)
            out[mode] = {"before": before, "after": after, "updates": used}
        res[C_] = dict(out, n_feedback=len(fb), n_test=len(tc), test_runs=len(runs) - 1)
        md.append("| %s | %d / %d | %.3f | %.3f (%d/%d) | %.3f | %.3f | %.3f |" % (
            C_, len(tc), len(runs) - 1, out["confirmed"]["before"]["recall"], out["self"]["after"]["recall"],
            out["self"]["updates"], len(fb), out["confirmed"]["after"]["recall"],
            out["confirmed"]["before"]["fpr"], out["confirmed"]["after"]["fpr"]))
    md += ["", "Feedback-episode sizes: " + ", ".join("%s %d windows" % (k, v["n_feedback"]) for k, v in res.items()) + ".", "",
           "Reading guide: 'before' is the unseen-class detection rate of the supervised core. Self-training can only help "
           "if some novel windows already score ≥ 0.95; otherwise it makes zero updates. Confirmed updates move only the SGD "
           "part, which carries 40% of the fused score (EXP-4 B)."]
    write("EXP-9_feedback_loop", md, res)
    return res


# ------------------------------------------------------------------ EXP-10
def exp10(d, o3, n):
    md = ["# EXP-10: Autoencoder and unknown-threat detection (leave-one-class-out)", ""] + HEADER + [
        "For each attack class C: every detector is trained on the primary split's training runs **with all C windows "
        "removed**, then tested on all C windows (as an unseen attack) plus the benign test runs. The benign-only "
        "detectors never see attack labels, so for them this equals their normal operation.", "",
        "| Detector | " + " | ".join("recall on unseen %s" % a for a in ATTACKS) + " | benign FPR (mean) |",
        "|---" * (len(ATTACKS) + 2) + "|"]
    res = {}
    tr0, te0 = primary_split(d)
    btest = te0[d.y[te0] == 0]
    keys = [PAPER, "Random forest", "Logistic regression", "Autoencoder (benign-only)", "Isolation forest (benign-only)"]
    for k in keys:
        row, fprs = [], []
        res[k] = {}
        for C_ in ATTACKS:
            tr = np.array([i for i in tr0 if d.c[i] != C_])
            te = np.r_[np.where(d.c == C_)[0], btest]
            m, _ = run_det(DETECTORS[k], sub(d, tr), sub(d, te))
            res[k][C_] = m; row.append("%s (%d/%d ep)" % (fmt_ci(m, "recall"), m["episodes_detected"], m["episodes"])); fprs.append(m["fpr"])
        md.append("| %s | %s | %.3f |" % (k, " | ".join(row), float(np.mean(fprs))))
    # hybrid OR rule: would adding the AE as an independent trigger help?
    md += ["", "## Would the autoencoder help if it could trigger on its own?", "",
           "Rule tested: alert if fused ≥ 0.35 **or** anomaly ≥ 1.0 (the deployed system does NOT do this; see EXP-4 C).", "",
           "| Unseen class | fused only: recall / FPR | fused OR anomaly: recall / FPR |", "|---|---|---|"]
    res["or_rule"] = {}
    for C_ in ATTACKS:
        tr = np.array([i for i in tr0 if d.c[i] != C_]); te = np.r_[np.where(d.c == C_)[0], btest]
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        conf = hm.core.threat_probability(d.X[te]); an = np.clip(hm._recon_err(d.X[te]) / hm.ae_err_ref, 0, 10)
        a = metrics(d.y[te], conf >= 0.35); b = metrics(d.y[te], (conf >= 0.35) | (an >= 1.0))
        res["or_rule"][C_] = {"fused": a, "or": b}
        md.append("| %s | %.3f / %.3f | %.3f / %.3f |" % (C_, a["recall"], a["fpr"], b["recall"], b["fpr"]))
    md += ["", "Caveat: the benign test set is 2 runs (63 windows), so FPR resolution is about 1.6% per window and the "
           "Wilson intervals are wide. The 99th-percentile threshold implies ~1% FPR on benign data like the training benign."]
    write("EXP-10_autoencoder_unknown", md, res)
    return res


# ------------------------------------------------------------------ EXP-6
def exp6(d, o3, n):
    md = ["# EXP-6: Statistical robustness", ""] + HEADER
    res = {}
    # 1) training-seed variance on the fixed primary split
    tr, te = primary_split(d)
    md += ["## A. Training-seed variance (primary split, 20 seeds)", "",
           "Only the model's random seed changes (XGBoost subsampling, SGD order, MLP init); data split fixed.", "",
           "| Detector | F1 mean ± sd | Recall mean ± sd | FPR mean ± sd |", "|---|---|---|---|"]
    saved = tm.SEED
    for k in (PAPER, "Random forest", "Autoencoder (benign-only)"):
        ms = []
        for s in range(20):
            tm.SEED = s
            ms.append(run_det(DETECTORS[k], sub(d, tr), sub(d, te))[0])
        tm.SEED = saved
        f, r, fp = (summarize([m[x] for m in ms]) for x in ("f1", "recall", "fpr"))
        res.setdefault("seed", {})[k] = {"f1": f, "recall": r, "fpr": fp}
        md.append("| %s | %.3f ± %.3f | %.3f ± %.3f | %.3f ± %.3f |" % (k, f["mean"], f["std"], r["mean"], r["std"], fp["mean"], fp["std"]))
    md.append("\n(The paper model's XGBoost uses colsample 0.3, so the seed changes which features each tree sees.)\n")
    # 2) split variance for the paper model, broken down
    md += ["## B. Split-to-split variance of the paper model (n = %d grouped splits)" % n, ""]
    ms = repeated(d, [PAPER], n)[PAPER]
    f = summarize([m["f1"] for m in ms]); r = summarize([m["recall"] for m in ms]); fp = summarize([m["fpr"] for m in ms])
    res["split"] = {"f1": f, "recall": r, "fpr": fp}
    md += ["| Metric | mean | sd | 2.5 pct | 97.5 pct |", "|---|---|---|---|---|"]
    for name, s in (("F1", f), ("Recall", r), ("FPR", fp)):
        md.append("| %s | %.3f | %.3f | %.3f | %.3f |" % (name, s["mean"], s["std"], s["p2.5"], s["p97.5"]))
    md += ["", "Per-class recall over splits:", "", "| Class | mean | sd | min | splits with recall < 0.5 |", "|---|---|---|---|---|"]
    for a in ATTACKS:
        v = np.array([m["recall_by_class"][a]["recall"] for m in ms if a in m["recall_by_class"]])
        res.setdefault("per_class", {})[a] = summarize(v)
        md.append("| %s | %.3f | %.3f | %.3f | %.0f%% |" % (a, v.mean(), v.std(ddof=1), v.min(), 100 * (v < 0.5).mean()))
    # 3) pooled Wilson CI over the repeated splits is NOT valid (windows reused); state that
    md += ["", "Pooling windows across repeated splits would count the same window many times, so no pooled CI is "
           "reported. Use the percentile intervals above (split variability) together with the Wilson CIs of the "
           "primary split (sampling variability within one split).", ""]
    # 4) cross-session gap
    md += ["## C. Within-session vs cross-session (scan + benign only)", "",
           "Same model trained on all Oct 16/19 data. Within-session numbers use the repeated splits restricted to scan "
           "and benign windows; cross-session uses Oct 3.", "",
           "| Setting | scan recall | benign FPR |", "|---|---|---|"]
    ws_r = [m["recall_by_class"]["scan"]["recall"] for m in ms if "scan" in m["recall_by_class"]]
    o, _ = run_det(DETECTORS[PAPER], d, o3)
    res["cross_session"] = {"within_scan_recall": summarize(ws_r), "within_fpr": fp, "oct3": o}
    md.append("| within session (repeated splits) | %.3f ± %.3f | %.3f ± %.3f |" % (np.mean(ws_r), np.std(ws_r, ddof=1), fp["mean"], fp["std"]))
    md.append("| cross session (Oct 3) | %s (%d/%d runs) | %s |" % (fmt_ci(o, "recall"), o["episodes_detected"], o["episodes"], fmt_ci(o, "fpr")))
    md += ["", "Oct 3 scans are `nmap -T4 -p 1-1000` (about 1 s each, one 5-s window per run) while Oct 16 scans are "
           "`-p 1-65535`; a gap here mixes session shift with attack-variant shift and cannot separate them."]
    write("EXP-6_statistical_robustness", md, res)
    return res


EXPS = {"exp3": exp3, "exp4": exp4, "exp5": exp5, "exp8": exp8, "exp9": exp9, "exp10": exp10, "exp6": exp6}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="+", help="all | " + " | ".join(EXPS))
    ap.add_argument("--n", type=int, default=100, help="repeated grouped splits (default 100)")
    a = ap.parse_args()
    which = list(EXPS) if "all" in a.which else a.which
    d, o3 = C.load_v3(), C.load_oct3()
    print("v3 supervised %d windows, %d runs; Oct 3 supervised %d windows" % (len(d.y), len(set(d.r)), len(o3.y)))
    meta = {"n_splits": a.n, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "experiments": which}
    for w in which:
        t = time.time()
        EXPS[w](d, o3, a.n)
        print("[%s] done in %.0f s" % (w, time.time() - t), flush=True)
    with open(os.path.join(C.OUT_DIR, "run_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)


if __name__ == "__main__":
    main()
