#!/usr/bin/env python3 -I
"""run_phase2b.py — remaining offline analyses (no twin needed). Reports in reports/phase2b/.

  python3 -I experiments/run_phase2b.py all [--n 100]
  python3 -I experiments/run_phase2b.py risk latency boundary grid kitnet

  risk      C11 / EXP-7 prep: blended risk score per class, incl. restore/boot ('healing') windows,
            and a data-based recommendation for the reinfection threshold (REINFECT_ABOVE, now 80)
  latency   EXP-2: detection latency per attack run with HELD-OUT models (old reports/latency_fp.md
            used the deployed model, which was trained on the very runs it timed)
  boundary  EXP-11: windows only partly inside their labelled run, and benign windows right after attacks
  grid      EXP-8 completion: policy threshold θ × risk weights grid, with heatmap
  kitnet    C4: KitNET-style ensemble of autoencoders on window features, vs the other benign-only detectors

Same designs as Phase 2: 100 grouped run-ID splits; models fitted on the training part only.
Status: PRELIMINARY (attacks from one session). Nothing copied from the paper.
"""
import argparse
import json
import math
import os
import sys
import time
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core as C  # noqa: E402
from core import ATTACKS, Data, sub, grouped_split, primary_split, summarize, wilson, metrics  # noqa: E402
import threat_model as tm  # noqa: E402
from threat_model_v3 import HybridModel, SEVERITY, RISK_W  # noqa: E402
from common import FEATURE_ORDER_V2  # noqa: E402
from sklearn.neural_network import MLPRegressor  # noqa: E402

OUT = os.path.join(C.ROOT, "reports", "phase2b")
MANIFEST = os.path.join(C.ROOT, "data", "run_manifest.jsonl")
HEADER = ["**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). "
          "Measured by `experiments/run_phase2b.py`; nothing copied from the paper.", ""]
CLASSES = ["benign"] + ATTACKS
HEAL_PG = "healing, post-grace (last 60 s)"
HEAL_ALL = "(healing, all windows incl. restore)"


# ------------------------------------------------------------------ data beyond supervised windows
def load_all():
    """Every window of dataset_v3 (all labels), with times."""
    rows = [json.loads(l) for l in open(C.DATA_V3) if l.strip()]
    X = np.array([[float(r["features"][k]) for k in FEATURE_ORDER_V2] for r in rows])
    return rows, X


def load_manifest():
    return {m["run_id"]: m for m in (json.loads(l) for l in open(MANIFEST) if l.strip())}


# ------------------------------------------------------------------ vectorised blended risk
def risk_parts(hm, X):
    """conf, anomaly, severity for many windows - same logic as HybridModel.assess()."""
    X = np.asarray(X, float)
    conf = hm.core.threat_probability(X)
    anom = hm.anomaly_score(X)
    sev = np.zeros(len(X))
    flagged = conf >= hm.core.cfg["t_suspicious"]          # assess(): class only when label != benign
    if hm.mc is not None and flagged.any():
        p = hm.mc.predict_proba(X[flagged])
        cls = [hm.mc_classes[i] for i in np.argmax(p, axis=1)]
        sev[flagged] = [SEVERITY.get(c, 0.0) for c in cls]
    return conf, anom, sev


def blended(conf, anom, sev, w_conf=RISK_W["confidence"], w_anom=RISK_W["anomaly"], w_sev=RISK_W["severity"]):
    r = w_conf * conf + w_anom * anom + w_sev * sev * conf
    return np.array([int(round(100 * float(v))) for v in np.clip(r, 0, 1)])


def streak_hit(scores, thr, k):
    """True if `k` consecutive values are > thr (healing_engine reinfection rule)."""
    run = 0
    for s in scores:
        run = run + 1 if s > thr else 0
        if run >= k:
            return True
    return False


# ------------------------------------------------------------------ RISK (C11)
def exp_risk(d, n):
    rows, Xall = load_all()
    heal_idx = [i for i, r in enumerate(rows) if r["label"] == "healing"]
    man = load_manifest()
    # The engine ignores a device for GRACE (90 s) after the restore finishes. The manifest does not record when
    # the restore command finished, only run stop = finish + pad; the documented pad is 150 s (record.sh,
    # collect_session.sh), and every Oct 16 healing run lasts ~218 s, consistent with that. So the windows the
    # verifier actually sees are those starting in the last 150 - 90 = 60 s of each healing run.
    post_grace = {i for i in heal_idx if rows[i]["window_start_epoch"] >= man[rows[i]["run_id"]]["stop_epoch"] - 60}
    heal_runs = defaultdict(list)
    for i in heal_idx:
        heal_runs[rows[i]["run_id"]].append(i)
    for rid in heal_runs:
        heal_runs[rid].sort(key=lambda i: rows[i]["window_start_epoch"])
    by_class = defaultdict(list)          # class -> risk values (held-out)
    anom_class = defaultdict(list)
    run_scores = defaultdict(list)        # (class, run, split) -> ordered risks, for streak rule
    heal_scores = []
    for s in range(n):
        tr, te = grouped_split(d, s)
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        conf, anom, sev = risk_parts(hm, d.X[te])
        rk = blended(conf, anom, sev)
        for c, r_, a_, rid in zip(d.c[te], rk, anom, d.r[te]):
            by_class[c].append(r_); anom_class[c].append(a_)
        for rid in sorted(set(d.r[te])):
            k = te[d.r[te] == rid]                    # supervised windows are in time order (checked by a test)
            run_scores[(d.c[k[0]], rid, s)] = list(rk[d.r[te] == rid])
        hc, ha, hs = risk_parts(hm, Xall[heal_idx])
        hr = blended(hc, ha, hs)
        by_class[HEAL_ALL] += list(hr); anom_class[HEAL_ALL] += list(ha)
        pos = {i: j for j, i in enumerate(heal_idx)}
        by_class[HEAL_PG] += [hr[pos[i]] for i in heal_idx if i in post_grace]
        anom_class[HEAL_PG] += [ha[pos[i]] for i in heal_idx if i in post_grace]
        for rid, idx in heal_runs.items():
            heal_scores.append((rid, s, [hr[pos[i]] for i in idx if i in post_grace], [hr[pos[i]] for i in idx]))
    md = ["# C11 — Blended risk score per class and the reinfection threshold", ""] + HEADER + [
        "risk = 100·(0.5·conf + 0.2·anomaly + 0.3·severity·conf), as `HybridModel.assess()` (vectorised; a unit test "
        "checks it equals `assess()`). Values pooled over %d grouped run-ID splits: each attack/benign window is scored "
        "only by models that did not train on its run. 'healing' = windows recorded while the twin was restored and "
        "rebooted (3 Oct 16 runs, never used for training). **Post-grace** = the last 60 s of each healing run: the "
        "engine ignores the device for 90 s after the restore ends and runs are labelled for 150 s after it, so only "
        "these windows reach the verifier (assumes the documented `--pad 150`; every healing run lasts ~218 s, consistent "
        "with it). An earlier draft of this analysis scored all healing windows; that overstates false reinfection and "
        "is kept only as a reference row." % n, "",
        "## Risk distribution", "",
        "| Class | windows×splits | median | p10 | p90 | ≥ 30 (act) | > 50 (strict) | > 70 (quarantine) | > 80 (reinfect) |",
        "|---|---|---|---|---|---|---|---|---|"]
    res = {"distribution": {}}
    for c in CLASSES + [HEAL_PG, HEAL_ALL]:
        v = np.array(by_class[c])
        row = {"n": int(len(v)), "median": float(np.median(v)), "p10": float(np.percentile(v, 10)),
               "p90": float(np.percentile(v, 90)), "ge30": float((v >= 30).mean()), "gt50": float((v > 50).mean()),
               "gt70": float((v > 70).mean()), "gt80": float((v > 80).mean())}
        res["distribution"][c] = row
        md.append("| %s | %d | %.0f | %.0f | %.0f | %.1f%% | %.1f%% | %.1f%% | %.1f%% |" % (
            c, row["n"], row["median"], row["p10"], row["p90"], 100 * row["ge30"], 100 * row["gt50"], 100 * row["gt70"], 100 * row["gt80"]))
    # streak rule, run level
    md += ["", "## Reinfection rule at run level: ≥ 2 consecutive windows above T", "",
           "The healing engine flags reinfection when REINFECT_STREAK (2) consecutive post-grace windows exceed "
           "REINFECT_ABOVE (80). For each T: share of attack runs that would trip the rule (wanted) and share of "
           "restore/boot runs that would trip it on their post-grace windows (false reinfection). Runs × splits.", "",
           "| T | " + " | ".join(ATTACKS) + " | benign runs | restore/boot, post-grace | (all restore/boot windows) |",
           "|---" * (len(ATTACKS) + 4) + "|"]
    res["streak"] = {}
    for T in (30, 40, 50, 60, 65, 70, 75, 80, 85, 90):
        cells, rowd = [], {}
        for c in ATTACKS + ["benign"]:
            v = [streak_hit(sc, T, 2) for (cc, rid, s), sc in run_scores.items() if cc == c]
            rowd[c] = float(np.mean(v)); cells.append("%.0f%%" % (100 * np.mean(v)))
        hv = [streak_hit(pg, T, 2) for (_, _, pg, _) in heal_scores]
        ha_ = [streak_hit(al, T, 2) for (_, _, _, al) in heal_scores]
        rowd["healing"] = float(np.mean(hv)); cells.append("%.0f%%" % (100 * np.mean(hv)))
        rowd["healing_all_windows"] = float(np.mean(ha_)); cells.append("(%.0f%%)" % (100 * np.mean(ha_)))
        res["streak"][T] = rowd
        md.append("| %d%s | %s |" % (T, " ← current" if T == 80 else "", " | ".join(cells)))
    # recommendation by a rule stated before looking: lowest T whose restore/boot false-reinfection rate is 0
    # (or the minimum), then report what it catches
    ok = [T for T in res["streak"] if res["streak"][T]["healing"] == 0 and res["streak"][T]["benign"] <= 0.05]
    rec = min(ok) if ok else min(res["streak"], key=lambda T: res["streak"][T]["healing"])
    res["recommended_T"] = rec
    md += ["", "**Rule fixed before reading the table**: choose the lowest T at which no restore/boot run (post-grace) and at most "
           "5%% of benign runs trip the 2-in-a-row rule (a false reinfection triggers another restore). "
           "Result: **T = %d** (currently 80). At T = %d the rule catches: %s." % (
               rec, rec, ", ".join("%s %.0f%%" % (c, 100 * res["streak"][rec][c]) for c in ATTACKS)),
           "", "Caveats: (1) the recommendation depends on which windows the verifier sees. Counting all healing windows "
           "(including the restore and early boot) no T below 90 avoids false reinfection (last column), which is why the "
           "deployed engine has a 90 s grace period. The post-grace set rests on the documented 150 s pad; Phase 3 R1 "
           "(5 clean heals) records exact restore-end times and must confirm this before `REINFECT_ABOVE` is changed. "
           "(2) Only 3 restore/boot runs exist, all from one day. (3) Beacon reinfection stays unreliable at any T (EXP-6).", "",
           "## Autoencoder anomaly score per class (EXP-10 detail)", "",
           "anomaly = reconstruction error / 99th percentile of benign training error, clipped to [0, 1]. "
           "(The code comment in `threat_model_v3.py` said 95th; the code uses the 99th — comment fixed.)", "",
           "| Class | median | p90 | share at 1.0 (≥ benign p99) |", "|---|---|---|---|"]
    for c in CLASSES + [HEAL_PG, HEAL_ALL]:
        v = np.array(anom_class[c])
        md.append("| %s | %.3f | %.3f | %.1f%% |" % (c, np.median(v), np.percentile(v, 90), 100 * (v >= 1.0).mean()))
        res.setdefault("anomaly", {})[c] = {"median": float(np.median(v)), "p90": float(np.percentile(v, 90)), "at1": float((v >= 1).mean())}
    write("C11_risk_score_analysis", md, res)
    return res


# ------------------------------------------------------------------ LATENCY (EXP-2)
def exp_latency(d, n):
    rows, Xall = load_all()
    man = load_manifest()
    starts = np.array([r["window_start_epoch"] for r in rows]); ends = np.array([r["window_end_epoch"] for r in rows])
    obs = defaultdict(lambda: defaultdict(list))     # level -> run -> latencies (None = missed)
    cls_of = {}
    for s in range(n):
        tr, te = grouped_split(d, s)
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        for rid in sorted(set(d.r[te][d.y[te] == 1])):
            m = man.get(rid)
            if m is None:
                continue
            st, sp = m["start_epoch"], m["stop_epoch"]
            k = np.where((ends > st) & (starts < sp + 5))[0]          # same matching as latency_fp.py
            k = k[np.argsort(starts[k])]
            conf, anom, sev = risk_parts(hm, Xall[k])
            rk = blended(conf, anom, sev)
            cls_of[rid] = m.get("attack_class") or "scan"
            for level, hit in (("fused ≥ 0.35 (alert)", conf >= 0.35), ("risk ≥ 30 (rate-limit)", rk >= 30),
                               ("risk > 70 (quarantine)", rk > 70)):
                j = np.where(hit)[0]
                obs[level][rid].append(max(0.0, ends[k[j[0]]] - st) if len(j) else None)
    md = ["# EXP-2 — Detection latency with held-out models", ""] + HEADER + [
        "Latency = end of the first flagged window − attack start (manifest), using the same window matching as "
        "`latency_fp.py` (windows overlapping the run, +5 s slack). Each attack run is timed only by models that did "
        "not train on it (%d grouped splits; each run is in the test part of ~30%% of splits). Per run, the median over "
        "those splits is taken; the table summarises runs. A run counts as detected if detected in > 50%% of its test splits. "
        "Pipeline and decision delays are not included (Phase 3 measures them live)." % n, ""]
    res = {}
    for level in obs:
        md += ["## " + level, "", "| Class | runs detected | median | p95 | max |", "|---|---|---|---|---|"]
        res[level] = {}
        allv = []
        for c in ATTACKS:
            runs = [r for r in obs[level] if cls_of[r] == c]
            det, lat = 0, []
            for r in runs:
                v = obs[level][r]
                hits = [x for x in v if x is not None]
                if len(hits) > len(v) / 2:
                    det += 1; lat.append(float(np.median(hits)))
            allv += lat
            res[level][c] = {"runs": len(runs), "detected": det, "latencies": lat}
            if lat:
                md.append("| %s | %d/%d | %.1f s | %.1f s | %.1f s |" % (c, det, len(runs), np.median(lat), np.percentile(lat, 95), max(lat)))
            else:
                md.append("| %s | 0/%d | — | — | — |" % (c, len(runs)))
        if allv:
            md.append("| **all** | %d/%d | %.1f s | %.1f s | %.1f s |" % (
                sum(res[level][c]["detected"] for c in ATTACKS), sum(res[level][c]["runs"] for c in ATTACKS),
                np.median(allv), np.percentile(allv, 95), max(allv)))
        md.append("")
    md += ["The old `reports/latency_fp.md` (median 5.0 s, all 22 runs detected) used `models_v3_hybrid`, trained on "
           "these same runs; it is superseded by this table."]
    write("EXP-2_latency_heldout", md, res)
    return res


# ------------------------------------------------------------------ BOUNDARY (EXP-11)
def exp_boundary(d, n):
    rows, Xall = load_all()
    man = load_manifest()
    sup = [i for i, r in enumerate(rows) if r["label"] in ("benign", "malware")]
    assert len(sup) == len(d.y)
    overlap = np.zeros(len(sup)); after_attack = np.zeros(len(sup), bool)
    attacks = sorted((m["start_epoch"], m["stop_epoch"]) for m in man.values() if m["label"] == "malware")
    for j, i in enumerate(sup):
        r = rows[i]; m = man.get(r["run_id"])
        ws, we = r["window_start_epoch"], r["window_end_epoch"]
        overlap[j] = max(0.0, min(we, m["stop_epoch"]) - max(ws, m["start_epoch"])) if m else float("nan")
        if r["label"] == "benign":
            after_attack[j] = any(0 <= ws - sp <= 10 or (st < we and ws < sp) for st, sp in attacks)
    partial = overlap < 5 - 1e-6
    pred_sum = np.zeros(len(sup)); pred_n = np.zeros(len(sup))
    for s in range(n):
        tr, te = grouped_split(d, s)
        m = tm.ThreatModel(None, FEATURE_ORDER_V2).fit(d.X[tr], d.y[tr])
        p = m.threat_probability(d.X[te]) >= 0.35
        pred_sum[te] += p; pred_n[te] += 1
    rate = np.divide(pred_sum, pred_n, out=np.full(len(sup), np.nan), where=pred_n > 0)
    md = ["# EXP-11 — Label-boundary analysis", ""] + HEADER + [
        "A window gets the label of the run it overlaps (`stream/pipeline.Labeler`), even if only part of the 5 s is "
        "inside the run. 'Partial' = less than the full 5 s inside its run. Detection rate = share of test-split "
        "appearances in which the paper detector flagged the window (%d grouped splits)." % n, "",
        "| Class | windows | partial | detection rate, full windows | detection rate, partial windows |", "|---|---|---|---|---|"]
    res = {}
    for c in CLASSES:
        k = d.c == c
        f, p_ = k & ~partial & (pred_n > 0), k & partial & (pred_n > 0)
        res[c] = {"n": int(k.sum()), "partial": int((k & partial).sum()),
                  "rate_full": float(np.nanmean(rate[f])) if f.any() else None,
                  "rate_partial": float(np.nanmean(rate[p_])) if p_.any() else None}
        md.append("| %s | %d | %d | %s | %s |" % (c, res[c]["n"], res[c]["partial"],
                  "%.3f" % res[c]["rate_full"] if res[c]["rate_full"] is not None else "—",
                  "%.3f" % res[c]["rate_partial"] if res[c]["rate_partial"] is not None else "—"))
    b = d.c == "benign"
    fa, fo = rate[b & after_attack & (pred_n > 0)], rate[b & ~after_attack & (pred_n > 0)]
    res["benign_after_attack"] = {"n": int(len(fa)), "fp_rate": float(np.mean(fa)) if len(fa) else None,
                                  "other_n": int(len(fo)), "other_fp_rate": float(np.mean(fo)) if len(fo) else None}
    md += ["", "## Benign windows within 10 s after an attack run", "",
           "| Benign windows | n | false-alarm rate |", "|---|---|---|",
           "| ≤ 10 s after an attack ended | %d | %s |" % (len(fa), "%.3f" % np.mean(fa) if len(fa) else "—"),
           "| all other benign | %d | %s |" % (len(fo), "%.3f" % np.mean(fo) if len(fo) else "—"), "",
           "If partial windows are detected much less often than full ones, part of the measured miss rate is a labelling "
           "artefact (a window with 1 s of attack and 4 s of idle is labelled attack). Phase 4 sessions keep a 15 s gap "
           "before each attack and benign traffic after it, so both effects can be measured on independent data."]
    write("EXP-11_label_boundary", md, res)
    return res


# ------------------------------------------------------------------ GRID (EXP-8)
def exp_grid(d, n):
    thetas = [50, 55, 60, 65, 70, 75, 80, 85, 90]
    wconf = [0.3, 0.4, 0.5, 0.6, 0.7]
    ratios = [0.0, 0.25, 0.4, 0.5, 0.75, 1.0]     # share of (1 - w_conf) given to anomaly; 0.4 = deployed 0.2/0.5
    acc = defaultdict(list)
    for s in range(n):
        tr, te = grouped_split(d, s)
        hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
        conf, anom, sev = risk_parts(hm, d.X[te]); yt = d.y[te]
        for wc in wconf:
            for q in ratios:
                wa = round((1 - wc) * q, 4); ws = round((1 - wc) - wa, 4)
                rk = blended(conf, anom, sev, wc, wa, ws)
                for th in thetas:
                    m = metrics(yt, rk > th)
                    acc[(th, wc, q)].append((m["recall"], m["fpr"], m["f1"]))
    res = {"%d|%.1f|%.2f" % k: dict(zip(("recall", "fpr", "f1"), np.mean(v, axis=0).tolist())) for k, v in acc.items()}
    md = ["# EXP-8 (completion) — Quarantine threshold θ × risk weights", ""] + HEADER + [
        "Decision = quarantine when risk > θ. risk = w_conf·conf + w_anom·anomaly + w_sev·severity·conf, "
        "w_anom + w_sev = 1 − w_conf, split by the ratio r = w_anom / (w_anom + w_sev). Deployed: θ = 70, w_conf = 0.5, "
        "r = 0.4 (0.2 / 0.3). Means over %d grouped splits. **Descriptive only** — choosing a cell from this table would "
        "tune on test data; the Phase 4 validation sessions are for that." % n, ""]
    for metric in ("recall", "fpr"):
        md += ["## Mean %s at r = 0.4 (deployed ratio)" % ("quarantine recall" if metric == "recall" else "false-quarantine rate (FPR)"), "",
               "| θ \\ w_conf | " + " | ".join("%.1f" % w for w in wconf) + " |", "|---" * (len(wconf) + 1) + "|"]
        for th in thetas:
            cells = []
            for w in wconf:
                v = res["%d|%.1f|%.2f" % (th, w, 0.4)][metric]
                cells.append(("**%.3f**" if (th == 70 and w == 0.5) else "%.3f") % v)
            md.append("| %d | %s |" % (th, " | ".join(cells)))
        md.append("")
    md += ["## Effect of the anomaly / severity ratio (θ = 70, w_conf = 0.5)", "",
           "| r (anomaly share) | w_anom | w_sev | recall | FPR | F1 |", "|---|---|---|---|---|---|"]
    for q in ratios:
        v = res["%d|%.1f|%.2f" % (70, 0.5, q)]
        md.append("| %.2f%s | %.2f | %.2f | %.3f | %.3f | %.3f |" % (q, " ← deployed" if q == 0.4 else "", 0.5 * q, 0.5 * (1 - q), v["recall"], v["fpr"], v["f1"]))
    png = os.path.join(OUT, "EXP-8_grid_heatmap.png")
    heatmap(res, thetas, wconf, png)
    md += ["", "![quarantine recall and FPR heatmaps](EXP-8_grid_heatmap.png)", "",
           "Reading: with the anomaly term capped by its weight, θ above w_conf + w_anom·1 cannot be reached by anomaly alone; "
           "see EXP-4 C for the same limit at the action threshold of 30."]
    write("EXP-8_grid", md, res)
    return res


def heatmap(res, thetas, wconf, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    ramp = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]   # dataviz sequential blue 100->700
    cmap = LinearSegmentedColormap.from_list("seq_blue", ramp)
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 4.2), dpi=150)
    for ax, (metric, title) in zip(axes, (("recall", "Quarantine recall"), ("fpr", "False-quarantine rate (FPR)"))):
        M = np.array([[res["%d|%.1f|%.2f" % (th, w, 0.4)][metric] for w in wconf] for th in thetas])
        ax.imshow(M, cmap=cmap, vmin=0, vmax=max(1e-9, M.max()) if metric == "fpr" else 1, aspect="auto")
        for i in range(len(thetas)):
            for j in range(len(wconf)):
                v = M[i, j]
                dark = (v / (M.max() if metric == "fpr" and M.max() > 0 else 1)) > 0.55
                ax.text(j, i, "%.2f" % v, ha="center", va="center", fontsize=7.5,
                        color="#ffffff" if dark else "#1f2328",
                        fontweight="bold" if (thetas[i] == 70 and wconf[j] == 0.5) else "normal")
        ax.set_xticks(range(len(wconf)), ["%.1f" % w for w in wconf], fontsize=8)
        ax.set_yticks(range(len(thetas)), [str(t) for t in thetas], fontsize=8)
        ax.set_xlabel("w_conf (confidence weight)", fontsize=8.5, color="#57606a")
        ax.set_ylabel("θ (quarantine when risk > θ)", fontsize=8.5, color="#57606a")
        ax.set_title(title, fontsize=10, color="#1f2328", loc="left")
        for sp in ax.spines.values():
            sp.set_visible(False)
        ax.tick_params(length=0, colors="#57606a")
    fig.suptitle("Risk-weight grid at anomaly share r = 0.4 (deployed cell in bold: θ = 70, w_conf = 0.5)",
                 fontsize=9, color="#57606a", x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(path, facecolor="#ffffff")
    plt.close(fig)


# ------------------------------------------------------------------ KITNET-style (C4)
class KitNETStyle:
    """KitNET-style anomaly detector on WINDOW features (not packet-level Kitsune):
    features grouped by correlation (hierarchical clustering, ≤ m per group) on benign training windows,
    one small autoencoder per group, an output autoencoder over the groups' RMSEs.
    Score = output RMSE / its 99th percentile on benign training windows (≥ 1 = anomalous)."""

    def __init__(self, m=5, seed=0):
        self.m, self.seed = m, seed

    def fit(self, Xb):
        from scipy.cluster.hierarchy import linkage, fcluster
        from scipy.spatial.distance import squareform
        Xb = np.asarray(Xb, float)
        live = np.where(Xb.std(axis=0) > 0)[0]
        Z = Xb[:, live]
        corr = np.nan_to_num(np.corrcoef(Z.T), nan=0.0)
        dist = np.clip(1 - np.abs(corr), 0, None); np.fill_diagonal(dist, 0)
        L = linkage(squareform(dist, checks=False), "average")
        groups, k = [], 1
        while True:                       # smallest number of clusters whose groups are all ≤ m
            lab = fcluster(L, k, "maxclust")
            sizes = np.bincount(lab)[1:]
            if sizes.max() <= self.m or k >= len(live):
                break
            k += 1
        self.groups = [live[lab == g] for g in np.unique(lab)]
        self.aes = []
        for g in self.groups:
            ae = MLPRegressor(hidden_layer_sizes=(max(1, int(math.ceil(0.75 * len(g)))),), max_iter=800,
                              random_state=self.seed).fit(Xb[:, g], Xb[:, g])
            self.aes.append(ae)
        R = self._layer(Xb)
        self.lo, self.hi = R.min(axis=0), R.max(axis=0) + 1e-12
        Rn = (R - self.lo) / (self.hi - self.lo)
        self.out = MLPRegressor(hidden_layer_sizes=(max(1, int(math.ceil(0.75 * Rn.shape[1]))),), max_iter=800,
                                random_state=self.seed).fit(Rn, Rn)
        self.ref = float(np.percentile(self._out(Xb), 99)) or 1.0
        return self

    def _layer(self, X):
        return np.column_stack([np.sqrt(np.mean((X[:, g] - ae.predict(X[:, g]).reshape(len(X), -1)) ** 2, axis=1))
                                for g, ae in zip(self.groups, self.aes)])

    def _out(self, X):
        Rn = (self._layer(X) - self.lo) / (self.hi - self.lo)
        return np.sqrt(np.mean((Rn - self.out.predict(Rn).reshape(len(X), -1)) ** 2, axis=1))

    def score(self, X):
        return self._out(np.asarray(X, float)) / self.ref


def _kitnet_fit(X, y, c, names):
    k = KitNETStyle(seed=tm.SEED).fit(X[y == 0])
    return k.score


def exp_kitnet(d, n):
    dets = {"KitNET-style (benign-only)": C.Det("kitnet", _kitnet_fit, 1.0, "unsupervised"),
            "Autoencoder (benign-only)": C.DETECTORS["Autoencoder (benign-only)"],
            "Isolation forest (benign-only)": C.DETECTORS["Isolation forest (benign-only)"],
            "paper: fused XGB+SGD (aug)": C.DETECTORS["paper: fused XGB+SGD (aug)"]}
    reps = {k: [] for k in dets}
    for s in range(n):
        tr, te = grouped_split(d, s)
        for k, det in dets.items():
            reps[k].append(C.run_det(det, sub(d, tr), sub(d, te))[0])
    o3 = C.load_oct3()
    md = ["# C4 — KitNET-style baseline (benign-only)", ""] + HEADER + [
        "Kitsune works on per-packet statistics; this repo only has 5-s window features, so this is a **KitNET-style** "
        "ensemble on window features (feature groups by correlation, ≤ 5 features each, one autoencoder per group, an "
        "output autoencoder), trained on benign training windows only, threshold = 99th percentile of benign training "
        "score — the same rule as the other benign-only detectors. %d grouped run-ID splits." % n, "",
        "| Detector | F1 mean ± sd | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Oct 3 FPR | Oct 3 scan recall |",
        "|---|---|---|---|---|---|---|"]
    res = {}
    for k, det in dets.items():
        ms = reps[k]
        f, r, fp, auc = (summarize([m.get(x) for m in ms]) for x in ("f1", "recall", "fpr", "roc_auc"))
        o, _ = C.run_det(det, d, o3)
        res[k] = {"f1": f, "recall": r, "fpr": fp, "roc_auc": auc, "oct3": {"fpr": o["fpr"], "recall": o["recall"]},
                  "recall_by_class": {a: float(np.mean([m["recall_by_class"][a]["recall"] for m in ms if a in m["recall_by_class"]])) for a in ATTACKS}}
        md.append("| %s | %.3f ± %.3f | %.3f ± %.3f | %.3f ± %.3f | %.3f | %.3f | %.3f |" % (
            k, f["mean"], f["std"], r["mean"], r["std"], fp["mean"], fp["std"], auc["mean"], o["fpr"], o["recall"]))
    md += ["", "Per-class recall (mean over splits):", "", "| Detector | " + " | ".join(ATTACKS) + " |", "|---" * (len(ATTACKS) + 1) + "|"]
    for k in dets:
        md.append("| %s | %s |" % (k, " | ".join("%.3f" % res[k]["recall_by_class"][a] for a in ATTACKS)))
    write("C4_kitnet_baseline", md, res)
    return res


# ------------------------------------------------------------------ output
def write(name, md, obj=None):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name + ".md"), "w") as f:
        f.write("\n".join(md) + "\n")
    if obj is not None:
        with open(os.path.join(OUT, name + ".json"), "w") as f:
            json.dump(obj, f, indent=2, default=lambda o: o.tolist() if hasattr(o, "tolist") else (None if isinstance(o, float) and math.isnan(o) else str(o)))


EXPS = {"risk": exp_risk, "latency": exp_latency, "boundary": exp_boundary, "grid": exp_grid, "kitnet": exp_kitnet}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="+")
    ap.add_argument("--n", type=int, default=100)
    a = ap.parse_args()
    which = list(EXPS) if "all" in a.which else a.which
    d = C.load_v3()
    meta = {"n_splits": a.n, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "experiments": which}
    for w in which:
        t = time.time(); EXPS[w](d, a.n); print("[%s] done in %.0f s" % (w, time.time() - t), flush=True)
    with open(os.path.join(OUT, "run_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)


if __name__ == "__main__":
    main()
