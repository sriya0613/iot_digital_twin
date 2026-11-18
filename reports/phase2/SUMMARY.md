# Phase 2 Summary — experiments on the existing data

**Status**: PRELIMINARY. All training attacks come from one session (Oct 16). Every number below was measured by
`experiments/run_phase2.py` (100 grouped run-ID splits unless noted) or `experiments/shift_oct3.py`. Nothing is copied
from the paper. Reproduce with `python3 -I experiments/run_phase2.py all && python3 -I experiments/shift_oct3.py`.

## Headline findings

1. **The paper detector's single-split numbers are optimistic.** Over 100 grouped splits it has mean F1 0.759 ± 0.091
   (2.5–97.5 pct: 0.620–0.879), recall 0.676 ± 0.149, FPR 0.112 ± 0.165. The Phase 1 split (F1 0.821) is a favourable draw.
   Retraining with 20 seeds on that split moves F1 by only ± 0.005, so **which runs land in the test set matters far more than training randomness**.
2. **Simple baselines are not worse.** On identical splits, random forest (F1 0.855) and logistic regression (0.822) beat the
   paper model in 76–77% of splits, but at a clearly higher FPR (0.33 and 0.21 vs 0.11). The paper model trades recall for a low
   false-alarm rate; that is a design choice to state, not superiority to claim. (EXP-3)
3. **Scan augmentation lowers recall.** The same fused model without `augment_scans` reaches recall 0.963 vs 0.676, with FPR
   0.338 vs 0.112. (EXP-4)
4. **The three-monitor claim is not supported in its current form.** Adding syscall and/or energy features to network
   features *lowers* mean F1 by about 0.05 and is worse in ~72–75% of splits. Beacon recall drops from 0.474 (network only)
   to 0.170 (all 45). Syscall + energy alone (no network) scores highest (F1 0.840) but with FPR 0.246. (EXP-5)
5. **Beacon is barely detected.** Paper model beacon recall: mean 0.170, below 0.5 in 86% of splits. Bruteforce and DoS: 1.000. (EXP-6)
6. **The autoencoder cannot trigger containment.** In the blended risk formula, anomaly alone contributes at most
   0.2 × 100 = 20, below the action threshold of 30. On the primary split, removing the anomaly term changes the action for 3 of 127
   windows. Unknown-threat containment therefore depends entirely on the supervised core. (EXP-4 C)
7. **Unseen classes: mixed results.** With a class removed from training, the paper core still catches bruteforce and DoS
   (recall 1.0), half of scans (0.51), and **no beacons** (0.0). The benign-only autoencoder gets 0.03 on unseen beacon too. (EXP-10)
8. **Feedback loop.** Self-training (the deployed rule) cannot learn an unseen beacon: it never sees confident attack windows.
   Analyst-confirmed updates raise beacon recall from 0.00 to 0.68 but raise FPR from 0.016 to 0.508, because only the SGD part
   learns. (EXP-9)
9. **Cross-session generalisation fails.** Trained on Oct 16/19, tested on Oct 3: every scan run is detected, but the paper model
   false-alarms on **25 of 37 (68%)** benign windows. The diagnostic (EXP-6b) points to host-dependent energy features
   (`energy_cpu_util`, KS 0.96) and a different network setup on Oct 3 (host-run nmap, no `atk` namespace). Network-only still has 54%
   FPR there. Oct 3 differs in environment as well as session, so this cannot be read as pure session drift.
10. **Threshold.** In the descriptive sweep, mean F1 is highest at threshold 0.05 (0.825 vs 0.759 at the deployed 0.35). This was not
    tuned on held-out data; confirm it on Phase 4 validation sessions before changing anything.

## What this means for the manuscript

- Report detection as a distribution over grouped splits (mean ± sd and percentile range), plus Wilson CIs for a single
  pre-registered split. Do not report one random-split number.
- Do not claim that the syscall and energy monitors improve detection; on this data they do not. Report EXP-5 as it is, and say
  the syscall hook covers 4 network syscalls (5 of 11 syscall features are constant).
- Do not claim unknown-threat (zero-day) containment through the autoencoder: the risk formula prevents it.
- Report beacon as a weakness.
- State that cross-session performance is unknown pending Phase 4; Oct 3 shows a large FPR rise under a changed environment.

## Required before final claims (Phase 3/4)

- ≥ 15 new sessions with fixed topology (`scripts/run_protocol.sh`), session-level train/val/test assignment fixed in advance.
- Per-session normalisation of energy features (or drop them) and log host load during collection.
- Choose threshold, fusion weights and augmentation on validation sessions only; test once.
- Consider: allowing the anomaly score to trigger rate-limiting on its own; better beacon features (periodicity / inter-request timing
  across windows); also updating XGBoost (not only SGD) from confirmed feedback.

## Files

| Experiment | Report |
|---|---|
| EXP-3 baselines | `EXP-3_baselines.md` |
| EXP-4 detector ablation + policy-level risk | `EXP-4_detector_ablation.md` |
| EXP-5 monitor ablation | `EXP-5_monitor_ablation.md` |
| EXP-6 statistical robustness | `EXP-6_statistical_robustness.md` |
| EXP-6b Oct 3 shift diagnostic | `EXP-6b_oct3_shift.md` |
| EXP-8 sensitivity | `EXP-8_sensitivity.md` |
| EXP-9 feedback loop | `EXP-9_feedback_loop.md` |
| EXP-10 autoencoder / unknown threats | `EXP-10_autoencoder_unknown.md` |
| Collection kit (Phase 4) | `../../scripts/COLLECTION_PROTOCOL.md` |
