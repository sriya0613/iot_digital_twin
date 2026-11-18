# EXP-3: Baselines vs the paper's detector

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

Same splits, features (all 45) and train-only fitting for every detector. Decision thresholds are fixed in advance: 0.35 for the paper's fused score (its deployed value), 0.5 for other classifiers' probabilities, and the 99th percentile of benign training scores for the two benign-only detectors.

## A. Primary run-ID split (Phase 1 split; 127 test windows, 8 test runs)

| Detector | Precision [95% CI] | Recall [95% CI] | FPR [95% CI] | F1 | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.958 [0.860, 0.988] | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 0.821 | 0.930 | 5/6 |
| fused XGB+SGD (no aug) | 0.899 [0.805, 0.950] | 0.969 [0.893, 0.991] | 0.111 [0.055, 0.212] | 0.932 | 0.972 | 6/6 |
| XGBoost only (aug) | 0.958 [0.860, 0.988] | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 0.821 | 0.956 | 5/6 |
| SGD only (aug) | 1.000 [0.921, 1.000] | 0.703 [0.582, 0.801] | 0.000 [0.000, 0.057] | 0.826 | 0.845 | 5/6 |
| Random forest | 0.939 [0.854, 0.976] | 0.969 [0.893, 0.991] | 0.063 [0.025, 0.152] | 0.954 | 0.984 | 6/6 |
| Random forest (aug) | 0.866 [0.764, 0.928] | 0.906 [0.810, 0.956] | 0.143 [0.077, 0.250] | 0.885 | 0.967 | 6/6 |
| Logistic regression | 0.982 [0.907, 0.997] | 0.875 [0.772, 0.935] | 0.016 [0.003, 0.085] | 0.926 | 0.929 | 6/6 |
| One-rule threshold | 0.962 [0.872, 0.990] | 0.797 [0.683, 0.877] | 0.032 [0.009, 0.109] | 0.872 | 0.883 | 5/6 |
| Autoencoder (benign-only) | 0.979 [0.889, 0.996] | 0.719 [0.599, 0.814] | 0.016 [0.003, 0.085] | 0.829 | 0.927 | 6/6 |
| Isolation forest (benign-only) | 0.978 [0.887, 0.996] | 0.703 [0.582, 0.801] | 0.016 [0.003, 0.085] | 0.818 | 0.829 | 5/6 |

One-rule baseline chose: `energy_cpu_util` >= 0.1008 (on the training split).

## B. Repeated grouped splits (n = 100)

Per class ~30%% of run_ids held out per split. Every split has 1 test episode of beacon and bruteforce (only 3 and 4 exist), so per-split numbers are noisy; the spread below is the honest uncertainty.

| Detector | F1 mean ± sd [2.5, 97.5 pct] | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.759 ± 0.091 [0.620, 0.879] | 0.676 ± 0.149 | 0.112 ± 0.165 | 0.907 | 0.933 |
| fused XGB+SGD (no aug) | 0.874 ± 0.077 [0.717, 0.993] | 0.963 ± 0.051 | 0.338 ± 0.278 | 0.942 | 1.000 |
| XGBoost only (aug) | 0.764 ± 0.092 [0.621, 0.879] | 0.678 ± 0.147 | 0.104 ± 0.160 | 0.913 | 0.935 |
| SGD only (aug) | 0.760 ± 0.102 [0.624, 0.875] | 0.623 ± 0.130 | 0.000 ± 0.000 | 0.865 | 0.833 |
| Random forest | 0.855 ± 0.072 [0.723, 0.983] | 0.927 ± 0.071 | 0.332 ± 0.270 | 0.942 | 1.000 |
| Random forest (aug) | 0.815 ± 0.075 [0.677, 0.951] | 0.850 ± 0.132 | 0.306 ± 0.256 | 0.930 | 1.000 |
| Logistic regression | 0.822 ± 0.096 [0.632, 0.961] | 0.818 ± 0.165 | 0.209 ± 0.226 | 0.937 | 0.993 |
| One-rule threshold | 0.778 ± 0.081 [0.632, 0.905] | 0.753 ± 0.141 | 0.235 ± 0.217 | 0.759 | 0.953 |
| Autoencoder (benign-only) | 0.692 ± 0.135 [0.427, 0.882] | 0.567 ± 0.162 | 0.069 ± 0.138 | 0.795 | 0.847 |
| Isolation forest (benign-only) | 0.635 ± 0.196 [0.215, 0.867] | 0.502 ± 0.205 | 0.019 ± 0.046 | 0.757 | 0.835 |

### Paired comparison with the paper model (same splits)

| Detector | mean ΔF1 (det − paper) | splits where det F1 > paper | mean ΔFPR |
|---|---|---|---|
| fused XGB+SGD (no aug) | +0.115 | 78% | +0.227 |
| XGBoost only (aug) | +0.005 | 42% | -0.007 |
| SGD only (aug) | +0.000 | 39% | -0.112 |
| Random forest | +0.096 | 76% | +0.221 |
| Random forest (aug) | +0.056 | 71% | +0.194 |
| Logistic regression | +0.062 | 77% | +0.098 |
| One-rule threshold | +0.019 | 63% | +0.124 |
| Autoencoder (benign-only) | -0.067 | 25% | -0.043 |
| Isolation forest (benign-only) | -0.124 | 25% | -0.093 |

## C. Cross-session: train on Oct 16 + Oct 19, test on Oct 3

Oct 3 test set: 37 benign windows (1 run), 9 scan windows (9 separate nmap runs, `-p 1-1000`, class inferred from the manifest command). This is the only test data from an independent session.

| Detector | Precision [95% CI] | Recall [95% CI] | FPR [95% CI] | F1 | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.265 [0.146, 0.431] | 1.000 [0.701, 1.000] | 0.676 [0.515, 0.804] | 0.419 | 1.000 | 9/9 |
| fused XGB+SGD (no aug) | 0.196 [0.107, 0.332] | 1.000 [0.701, 1.000] | 1.000 [0.906, 1.000] | 0.327 | 0.955 | 9/9 |
| XGBoost only (aug) | 0.300 [0.167, 0.479] | 1.000 [0.701, 1.000] | 0.568 [0.409, 0.713] | 0.462 | 0.964 | 9/9 |
| SGD only (aug) | 0.643 [0.388, 0.837] | 1.000 [0.701, 1.000] | 0.135 [0.059, 0.280] | 0.783 | 1.000 | 9/9 |
| Random forest | 0.237 [0.130, 0.392] | 1.000 [0.701, 1.000] | 0.784 [0.628, 0.886] | 0.383 | 0.995 | 9/9 |
| Random forest (aug) | 0.225 [0.123, 0.375] | 1.000 [0.701, 1.000] | 0.838 [0.689, 0.923] | 0.367 | 0.892 | 9/9 |
| Logistic regression | 0.360 [0.202, 0.555] | 1.000 [0.701, 1.000] | 0.432 [0.287, 0.591] | 0.529 | 0.997 | 9/9 |
| One-rule threshold | 0.281 [0.156, 0.454] | 1.000 [0.701, 1.000] | 0.622 [0.461, 0.759] | 0.439 | 0.689 | 9/9 |
| Autoencoder (benign-only) | 0.529 [0.310, 0.738] | 1.000 [0.701, 1.000] | 0.216 [0.114, 0.372] | 0.692 | 0.793 | 9/9 |
| Isolation forest (benign-only) | 0.538 [0.291, 0.768] | 0.778 [0.453, 0.937] | 0.162 [0.077, 0.311] | 0.636 | 0.910 | 7/9 |

## Reading

Across 100 repeated splits the paper detector's mean F1 is 0.759 (sd 0.091). The highest mean F1 is **fused XGB+SGD (no aug)** at 0.874. Differences smaller than about one standard deviation should not be reported as improvements. These are window-level results on a dataset whose attacks come from one session; the Oct 3 table is the only cross-session evidence and covers scans only.
