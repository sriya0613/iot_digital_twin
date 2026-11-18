# Phase 2b Summary — remaining offline analyses

**Status**: PRELIMINARY. Attacks in training all come from one session (Oct 16). Every number was measured by
`experiments/run_phase2b.py` (100 grouped run-ID splits; each window/run is scored only by models that did not
train on its run). Reproduce: `python3 -I experiments/run_phase2b.py all`.

## Findings

1. **Detection latency with held-out models (EXP-2).** Alert (fused ≥ 0.35): 21 of 22 attack runs detected,
   median 3.6 s, p95 17.1 s (scan median 16.6 s, bruteforce 2.7 s, DoS 2.7 s, beacon 2 of 3 runs, 6.7 s).
   Quarantine (risk > 70): 19 of 22 runs — **no beacon run ever reaches quarantine**. The old
   `reports/latency_fp.md` (median 5.0 s, 22/22) used a model trained on the runs it timed and is superseded.
2. **Rate-limiting fires often on benign traffic.** 19.7% of benign windows reach risk ≥ 30 (the rate-limit band);
   3.8% exceed 50; none exceed 70. Quarantine never hit a benign window in any split. The availability cost of the
   rate-limit band has to be measured live (EXP-12 e).
3. **Reinfection threshold (C11).** After the 90 s grace period, restore/boot windows stay low (median 14, p90 35,
   none above 50). By a rule fixed before reading the results (lowest T where no post-grace restore/boot run and
   ≤ 5% of benign runs trip the 2-in-a-row rule), **T = 50** instead of the current 80; at T = 50 every scan,
   bruteforce and DoS run would still trip it, beacon 3%. Scored over *all* healing windows (restore + early boot),
   no T below 90 avoids false reinfection — the grace period is what makes a lower threshold possible.
   **Not to be changed yet**: it relies on the documented 150 s labelling pad to locate the post-grace windows and
   on 3 restore runs from one day; Phase 3 R1 measures exact restore-end times.
4. **Weights hardly matter; the threshold does (EXP-8 grid).** At the deployed anomaly/severity ratio, quarantine
   recall moves by ≤ 0.01 across w_conf 0.3–0.7 for θ ≤ 70, and false quarantines are 0 for every θ ≥ 65. Recall
   falls sharply above θ = 80 (0.125 at θ = 90, w_conf = 0.5). Removing the anomaly term entirely (r = 0) lowers
   recall from 0.622 to 0.544 at θ = 70 — its effect is through the blend, not as an independent trigger (see EXP-4 C).
   Descriptive only; θ and weights are chosen on Phase 4 validation sessions.
5. **Label boundaries (EXP-11).** 15 of 45 scan windows are only partly inside their run; they are detected less
   often (0.498 vs 0.610 for full windows), so part of the scan miss rate is a labelling effect. The existing data
   contain **no** benign windows within 10 s after an attack, so post-attack false alarms cannot be measured yet;
   the v2 protocol adds benign traffic after every attack.
6. **KitNET-style baseline (C4).** A benign-only KitNET-style ensemble on window features reaches mean F1 0.751 ± 0.099,
   close to the supervised paper detector (0.759 ± 0.091) without any attack labels, and higher scan recall
   (0.750 vs 0.580), but beacon recall 0.015 and Oct 3 FPR 0.730. It is not packet-level Kitsune and is labelled as such.
7. Autoencoder detail (EXP-10): the code uses the 99th percentile of benign training error (the comment said 95th;
   comment fixed). Per-class anomaly distributions are in `C11_risk_score_analysis.md`.

## Files

| Analysis | Report |
|---|---|
| C11 risk score + reinfection threshold + anomaly per class | `C11_risk_score_analysis.md` |
| EXP-2 latency (held-out) | `EXP-2_latency_heldout.md` |
| EXP-11 label boundaries | `EXP-11_label_boundary.md` |
| EXP-8 θ × weights grid | `EXP-8_grid.md`, `EXP-8_grid_heatmap.png` |
| C4 KitNET-style baseline | `C4_kitnet_baseline.md` |
