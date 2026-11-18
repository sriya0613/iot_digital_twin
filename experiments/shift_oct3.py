#!/usr/bin/env python3 -I
"""shift_oct3.py — why does the Oct 16/19-trained detector false-alarm on Oct 3 benign traffic?

Compares benign windows of dataset_v3 (Oct 16 + Oct 19) with Oct 3 benign windows feature by
feature (two-sample KS statistic, share of Oct 3 values above the v3 benign maximum), and counts
which features SHAP blames for the false alarms. Writes reports/phase2/EXP-6b_oct3_shift.md.
"""
import os
import sys

import numpy as np
from scipy.stats import ks_2samp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import load_v3, load_oct3, write, FEATURE_ORDER_V2, ThreatModel, run_det, DETECTORS, FEATURE_SETS  # noqa: E402
from common import monitor_of  # noqa: E402

d, o = load_v3(), load_oct3()
b, ob = d.X[d.y == 0], o.X[o.y == 0]
rows = []
for j, f in enumerate(FEATURE_ORDER_V2):
    if np.ptp(b[:, j]) == 0 and np.ptp(ob[:, j]) == 0 and b[0, j] == ob[0, j]:
        continue
    rows.append((ks_2samp(b[:, j], ob[:, j]).statistic, f, b[:, j].mean(), ob[:, j].mean(), (ob[:, j] > b[:, j].max() + 1e-9).mean()))
rows.sort(reverse=True)

m = ThreatModel(None, FEATURE_ORDER_V2).fit(d.X, d.y)
flag = ob[m.threat_probability(ob) >= 0.35]
blame = {}
for x in flag:
    for e in m.feature_impact(x, top=3)[0]:
        if e["impact"] > 0:
            blame[e["feature"]] = blame.get(e["feature"], 0) + 1

md = ["# EXP-6b: Why the detector false-alarms on Oct 3 benign traffic", "",
      "**Status**: diagnostic. Model = paper detector trained on all Oct 16 + Oct 19 supervised windows.", "",
      "Oct 3 benign windows flagged: **%d of %d**." % (len(flag), len(ob)), "",
      "## Features that differ most (benign v3 vs benign Oct 3)", "",
      "| Feature | Monitor | KS | mean v3 benign | mean Oct 3 benign | Oct 3 above v3 max |", "|---|---|---|---|---|---|"]
md += ["| `%s` | %s | %.2f | %.4f | %.4f | %.0f%% |" % (f, monitor_of(f), ks, a, bb, 100 * hi) for ks, f, a, bb, hi in rows[:12]]
md += ["", "## Features SHAP blames for the false alarms (count of flagged windows where the feature is a top-3 risk-raising contributor)", ""]
md += ["- `%s` (%s): %d" % (f, monitor_of(f), n) for f, n in sorted(blame.items(), key=lambda t: -t[1])]
md += ["", "## Same model without the energy monitor", "", "| Feature set | Oct 3 benign FPR | Oct 3 scan recall |", "|---|---|---|"]
for name in ("network (28)", "network+syscall (39)", "all 3 monitors (45)"):
    mm, _ = run_det(DETECTORS["paper: fused XGB+SGD (aug)"], d, o, FEATURE_SETS[name])
    md.append("| %s | %.3f | %.3f |" % (name, mm["fpr"], mm["recall"]))
md += ["", "## Interpretation", "",
       "1. **Energy features are host-dependent.** `energy_cpu_util` and the power features measure the QEMU process on "
       "the host, so they move with host load and twin uptime, not only with what the device does. They separate the "
       "sessions almost perfectly (KS near 1) while carrying the label in training, which is a shortcut a model can learn.",
       "2. **Oct 3 used a different network setup.** Its manifest shows attacks run as `sudo nmap ...` from the host; Oct 16 "
       "ran them from the `atk` namespace. TTL, port-count and ICMP features shift accordingly, so Oct 3 differs in "
       "environment as well as session.",
       "3. Consequence for the paper: within-session results (EXP-3/5/6) do not show cross-session generalisation. "
       "Phase 4 sessions must keep the topology fixed and record host load, and the energy features need a per-session "
       "baseline normalisation (or removal) before they can be claimed as a benefit.",
       "", "Fixed topology for Phase 4 is enforced by `scripts/collect_session.sh` (all traffic from `atk`/`cli`)."]
write("EXP-6b_oct3_shift", md)
print("\n".join(md[:6]))
