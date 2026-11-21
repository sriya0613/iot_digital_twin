# Phase 2c B — Cross-window (temporal) features, declared variant

**Status**: PRELIMINARY — attacks from one session (Oct 16). Rules fixed in advance in `experiments/PHASE2C_PREREG.md` (committed before this run). Outer test parts never used for choices.

Paper detector (fused XGB+SGD with scan augmentation, threshold 0.35) on 100 grouped run-ID splits, with and without 10 causal rolling features (see the pre-registration). History resets after a recording gap > 30 s.

| Features | F1 mean ± sd [2.5, 97.5] | Recall | FPR | beacon recall | scan recall |
|---|---|---|---|---|---|
| all 45 | 0.759 ± 0.091 [0.620, 0.879] | 0.676 ± 0.149 | 0.112 ± 0.165 | 0.170 | 0.580 |
| all 45 + temporal (55) | 0.787 ± 0.107 [0.639, 0.931] | 0.712 ± 0.166 | 0.099 ± 0.163 | 0.328 | 0.627 |
| network 28 | 0.810 ± 0.103 [0.629, 0.930] | 0.754 ± 0.149 | 0.126 ± 0.194 | 0.474 | 0.520 |
| network 28 + temporal (38) | 0.837 ± 0.086 [0.689, 0.944] | 0.810 ± 0.121 | 0.163 ± 0.225 | 0.613 | 0.602 |

Paired, all 45 + temporal (55) vs all 45: mean ΔF1 +0.028 (better in 86%, worse in 13% of splits); mean Δ beacon recall +0.159.

Paired, network 28 + temporal (38) vs network 28: mean ΔF1 +0.027 (better in 74%, worse in 24% of splits); mean Δ beacon recall +0.140.

Caveat: only 3 beacon runs exist, all from Oct 16; every split tests on one of them. Rolling windows near a run boundary include the previous run's traffic, exactly as a live detector would see it.
