# Phase 2c Summary — pre-declared improvements

**Status**: PRELIMINARY — all attacks from one session (Oct 16). Candidates and selection rules were committed in
`experiments/PHASE2C_PREREG.md` (commit `b7387e9`) **before** running. Outer test parts were never used for any
choice. Reproduce: `python3 -I experiments/run_phase2c.py all`.

## A. Pipeline chosen by nested grouped evaluation (50 outer splits, 4 inner)

| Pipeline | F1 mean ± sd [2.5, 97.5 pct] | Recall | FPR | beacon recall | scan recall |
|---|---|---|---|---|---|
| chosen by nested evaluation | 0.846 ± 0.093 [0.635, 0.980] | 0.896 ± 0.142 | 0.296 ± 0.259 | 0.809 | 0.815 |
| paper model (all 45 features) | 0.757 ± 0.095 [0.620, 0.876] | 0.672 ± 0.156 | 0.114 ± 0.173 | 0.193 | 0.579 |

Paired: ΔF1 +0.088, better in 66% / worse in 28% of splits; **ΔFPR +0.183** — the gain is recall bought with
more false alarms (the pre-declared criterion was F1). Choice was not stable: network-28 features were chosen in
33/50 outer splits; fused XGB+SGD without scan augmentation in 25/50.

## B. Cross-window (temporal) features — declared variant (100 splits)

| Features | F1 | Recall | FPR | beacon recall |
|---|---|---|---|---|
| all 45 | 0.759 ± 0.091 | 0.676 | 0.112 | 0.170 |
| all 45 + temporal | 0.787 ± 0.107 | 0.712 | 0.099 | 0.328 |
| network 28 | 0.810 ± 0.103 | 0.754 | 0.126 | 0.474 |
| network 28 + temporal | 0.837 ± 0.086 | 0.810 | 0.163 | 0.613 |

Temporal features help in 86% (all 45) and 74% (network 28) of paired splits, mainly for beacon
(+0.16 / +0.14 recall). Only 3 beacon runs exist; each split tests on one of them.

## C. Anomaly score as an independent trigger (100 splits) — negative result

Act if risk ≥ 30 OR anomaly ≥ 1: recall 0.707 → 0.713, FPR 0.181 → 0.227. For an unseen class it adds little
(scan 0.51 → 0.60; beacon 0.00 → 0.03 window recall, 0 → 2 of 3 episodes touched). Not adopted.

## What this changes in the paper

- Report the nested-selection result as the method's held-out performance, with its FPR, and the paper's
  fixed configuration alongside it. Do not report the best outer cell.
- Temporal features are a justified, declared extension for periodic attacks.
- The autoencoder adds little as a trigger on this data; keep it as an explanatory signal, not a detection claim.
