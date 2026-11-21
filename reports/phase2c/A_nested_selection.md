# Phase 2c A — Pipeline chosen by nested grouped evaluation

**Status**: PRELIMINARY — attacks from one session (Oct 16). Rules fixed in advance in `experiments/PHASE2C_PREREG.md` (committed before this run). Outer test parts never used for choices.

12 candidates (4 models × 3 feature sets). In each of 50 outer grouped run-ID splits, the candidate with the highest mean F1 over 4 inner grouped splits **of the outer training part** is refitted on it and scored once on the outer test part.

## Outer results (same splits)

| Pipeline | F1 mean ± sd [2.5, 97.5] | Recall | FPR | beacon recall | scan recall |
|---|---|---|---|---|---|
| selected by nested evaluation | 0.846 ± 0.093 [0.635, 0.980] | 0.896 ± 0.142 | 0.296 ± 0.259 | 0.809 | 0.815 |
| paper model (all 45) | 0.757 ± 0.095 [0.620, 0.876] | 0.672 ± 0.156 | 0.114 ± 0.173 | 0.193 | 0.579 |

Paired (same outer splits): mean ΔF1 +0.088; selected better in 66%, worse in 28% of splits; mean ΔFPR +0.183.

## How often each candidate was selected

| Model | Features | times |
|---|---|---|
| fused XGB+SGD (no aug) | network 28 | 17 |
| Logistic regression | network 28 | 9 |
| paper: fused XGB+SGD (aug) | network 28 | 5 |
| fused XGB+SGD (no aug) | all 45 | 4 |
| fused XGB+SGD (no aug) | network+syscall 39 | 4 |
| Random forest | network+syscall 39 | 3 |
| paper: fused XGB+SGD (aug) | all 45 | 3 |
| Random forest | all 45 | 2 |
| Random forest | network 28 | 2 |
| Logistic regression | all 45 | 1 |

Allowed claim: *a pipeline chosen this way* reaches the outer numbers above on held-out runs. The selection frequency shows how stable the choice is; it is not a ranking of candidates.
