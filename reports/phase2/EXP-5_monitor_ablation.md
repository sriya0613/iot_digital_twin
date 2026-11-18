# EXP-5: Monitor (feature-group) ablation

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

Paper detector retrained on each feature subset, same splits. Note 8 features are constant in this dataset (3 network, 5 syscall), so the syscall monitor contributes 6 live features, not 11.

## A. Repeated grouped splits (n = 100)

| Detector | F1 mean ± sd [2.5, 97.5 pct] | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|
| network (28) | 0.810 ± 0.103 [0.629, 0.930] | 0.754 ± 0.149 | 0.126 ± 0.194 | 0.892 | 0.975 |
| network+syscall (39) | 0.761 ± 0.085 [0.626, 0.884] | 0.690 ± 0.137 | 0.145 ± 0.196 | 0.888 | 0.943 |
| network+energy (34) | 0.759 ± 0.097 [0.621, 0.884] | 0.665 ± 0.150 | 0.087 ± 0.160 | 0.908 | 0.905 |
| syscall+energy (17) | 0.840 ± 0.076 [0.709, 0.972] | 0.857 ± 0.124 | 0.246 ± 0.177 | 0.911 | 1.000 |
| all 3 monitors (45) | 0.759 ± 0.091 [0.620, 0.879] | 0.676 ± 0.149 | 0.112 ± 0.165 | 0.907 | 0.933 |
| effective non-constant (37) | 0.760 ± 0.094 [0.624, 0.882] | 0.674 ± 0.152 | 0.104 ± 0.161 | 0.907 | 0.932 |

### Paired gain over network-only (same splits)

| Feature set | mean ΔF1 | splits better | splits worse |
|---|---|---|---|
| network+syscall (39) | -0.048 | 8% | 75% |
| network+energy (34) | -0.050 | 16% | 73% |
| syscall+energy (17) | +0.031 | 65% | 35% |
| all 3 monitors (45) | -0.051 | 16% | 72% |
| effective non-constant (37) | -0.050 | 16% | 73% |

## B. Primary split

| Detector | Precision [95% CI] | Recall [95% CI] | FPR [95% CI] | F1 | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|---|
| network (28) | 0.962 [0.870, 0.989] | 0.781 [0.666, 0.865] | 0.032 [0.009, 0.109] | 0.862 | 0.853 | 6/6 |
| network+syscall (39) | 1.000 [0.923, 1.000] | 0.719 [0.599, 0.814] | 0.000 [0.000, 0.057] | 0.836 | 0.868 | 6/6 |
| network+energy (34) | 0.959 [0.863, 0.989] | 0.734 [0.615, 0.827] | 0.032 [0.009, 0.109] | 0.832 | 0.919 | 5/6 |
| syscall+energy (17) | 0.753 [0.649, 0.834] | 0.953 [0.871, 0.984] | 0.317 [0.216, 0.440] | 0.841 | 0.925 | 6/6 |
| all 3 monitors (45) | 0.958 [0.860, 0.988] | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 0.821 | 0.930 | 5/6 |
| effective non-constant (37) | 0.958 [0.860, 0.988] | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 0.821 | 0.937 | 5/6 |

## C. Cross-session (Oct 3)

| Detector | Precision [95% CI] | Recall [95% CI] | FPR [95% CI] | F1 | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|---|
| network (28) | 0.310 [0.173, 0.492] | 1.000 [0.701, 1.000] | 0.541 [0.384, 0.690] | 0.474 | 0.961 | 9/9 |
| network+syscall (39) | 0.375 [0.212, 0.573] | 1.000 [0.701, 1.000] | 0.405 [0.263, 0.565] | 0.545 | 1.000 | 9/9 |
| network+energy (34) | 0.273 [0.151, 0.442] | 1.000 [0.701, 1.000] | 0.649 [0.488, 0.782] | 0.429 | 0.982 | 9/9 |
| syscall+energy (17) | 0.220 [0.120, 0.367] | 1.000 [0.701, 1.000] | 0.865 [0.720, 0.941] | 0.360 | 0.778 | 9/9 |
| all 3 monitors (45) | 0.265 [0.146, 0.431] | 1.000 [0.701, 1.000] | 0.676 [0.515, 0.804] | 0.419 | 1.000 | 9/9 |
| effective non-constant (37) | 0.281 [0.156, 0.454] | 1.000 [0.701, 1.000] | 0.622 [0.461, 0.759] | 0.439 | 1.000 | 9/9 |

## D. Per-class recall, repeated splits (mean over splits containing the class)

| Feature set | scan | bruteforce | dos | beacon |
|---|---|---|---|---|
| network (28) | 0.520 | 1.000 | 1.000 | 0.474 |
| network+syscall (39) | 0.536 | 1.000 | 1.000 | 0.217 |
| network+energy (34) | 0.577 | 1.000 | 1.000 | 0.131 |
| syscall+energy (17) | 0.945 | 1.000 | 0.975 | 0.636 |
| all 3 monitors (45) | 0.580 | 1.000 | 1.000 | 0.170 |
| effective non-constant (37) | 0.577 | 1.000 | 1.000 | 0.169 |
