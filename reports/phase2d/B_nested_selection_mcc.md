# Phase 2d — Model and feature set chosen on training runs only (nested, in-split scaling)

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2d.py` with **min-max bounds refitted on the training runs of every split**.

12 candidates (4 models × 3 feature sets). In each of 50 outer splits the candidate with the highest mean **MCC** over 4 inner splits of the outer training part (ties: lower FPR, then the simpler feature set) is refitted and scored once on the outer test part. MCC replaces F1 as the criterion because F1 rewards flagging everything at this class mix (review E2).

| Pipeline | F1 | Recall | FPR | MCC | PR-AUC | scan | beacon |
|---|---|---|---|---|---|---|---|
| selected by nested evaluation | 0.796 | 0.804 | 0.269 | 0.559 | 0.932 | 0.737 | 0.562 |
| deployed recipe (45) | 0.753 | 0.672 | 0.122 | 0.547 | 0.940 | 0.590 | 0.190 |

Paired ΔMCC +0.012 (selected better in 46%, worse in 30% of splits; Wilcoxon p = 0.335).

| Model | Features | times selected |
|---|---|---|
| paper: fused XGB+SGD (aug) | all 45 | 11 |
| Logistic regression | network 28 | 10 |
| paper: fused XGB+SGD (aug) | network 28 | 10 |
| fused XGB+SGD (no aug) | network 28 | 6 |
| fused XGB+SGD (no aug) | all 45 | 3 |
| Logistic regression | all 45 | 3 |
| paper: fused XGB+SGD (aug) | network+syscall 39 | 2 |
| fused XGB+SGD (no aug) | network+syscall 39 | 2 |
| Random forest | network+syscall 39 | 1 |
| Random forest | all 45 | 1 |
| Logistic regression | network+syscall 39 | 1 |
