# EXP-8: Sensitivity analysis

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

These sweeps are **descriptive**: they show how results move with each setting. The deployed values (threshold 0.35, weights 0.6/0.4, actions at risk 30/70) were fixed in the code before this evaluation and are not re-tuned here, because choosing them on these test splits would leak test information.

## A. Decision threshold on the fused score (weights 0.6/0.4), n = 100 splits

| threshold | precision | recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.749 | 0.946 | 0.482 | 0.825 |
| 0.10 | 0.816 | 0.829 | 0.305 | 0.804 |
| 0.15 | 0.840 | 0.778 | 0.245 | 0.788 |
| 0.20 | 0.860 | 0.745 | 0.201 | 0.779 |
| 0.25 | 0.872 | 0.717 | 0.175 | 0.768 |
| 0.30 | 0.889 | 0.696 | 0.148 | 0.763 |
| 0.35 ← deployed | 0.914 | 0.676 | 0.112 | 0.759 |
| 0.40 | 0.932 | 0.658 | 0.084 | 0.755 |
| 0.45 | 0.946 | 0.643 | 0.064 | 0.751 |
| 0.50 | 0.954 | 0.638 | 0.054 | 0.751 |
| 0.55 | 0.965 | 0.632 | 0.040 | 0.752 |
| 0.60 | 0.982 | 0.626 | 0.021 | 0.755 |
| 0.65 | 0.994 | 0.625 | 0.008 | 0.758 |
| 0.70 | 1.000 | 0.625 | 0.000 | 0.761 |
| 0.75 | 1.000 | 0.624 | 0.000 | 0.761 |
| 0.80 | 1.000 | 0.623 | 0.000 | 0.759 |
| 0.85 | 1.000 | 0.620 | 0.000 | 0.757 |
| 0.90 | 1.000 | 0.611 | 0.000 | 0.750 |
| 0.95 | 1.000 | 0.593 | 0.000 | 0.737 |

## B. Fusion weight w_xgb (w_sgd = 1 − w_xgb), threshold 0.35

| w_xgb | recall | FPR | F1 | ROC-AUC |
|---|---|---|---|---|
| 0.0 | 0.625 | 0.000 | 0.761 | 0.865 |
| 0.1 | 0.626 | 0.002 | 0.761 | 0.876 |
| 0.2 | 0.627 | 0.019 | 0.757 | 0.885 |
| 0.3 | 0.637 | 0.043 | 0.754 | 0.894 |
| 0.4 | 0.648 | 0.069 | 0.753 | 0.900 |
| 0.5 | 0.659 | 0.092 | 0.753 | 0.904 |
| 0.6 ← deployed | 0.676 | 0.112 | 0.759 | 0.907 |
| 0.7 | 0.693 | 0.132 | 0.765 | 0.910 |
| 0.8 | 0.702 | 0.145 | 0.768 | 0.911 |
| 0.9 | 0.710 | 0.161 | 0.768 | 0.913 |
| 1.0 | 0.717 | 0.168 | 0.771 | 0.913 |

## C. Policy action threshold on the blended risk score (primary split)

| act when risk ≥ | recall | FPR | episodes detected |
|---|---|---|---|
| 10 | 0.984 [0.917, 0.997] | 0.937 [0.848, 0.975] | 6/6 |
| 20 | 0.922 [0.830, 0.966] | 0.079 [0.034, 0.173] | 6/6 |
| 30 ← rate-limit | 0.766 [0.649, 0.853] | 0.032 [0.009, 0.109] | 6/6 |
| 40 | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 5/6 |
| 50 | 0.703 [0.582, 0.801] | 0.032 [0.009, 0.109] | 5/6 |
| 60 | 0.703 [0.582, 0.801] | 0.000 [0.000, 0.057] | 5/6 |
| 70 ← quarantine | 0.703 [0.582, 0.801] | 0.000 [0.000, 0.057] | 5/6 |
| 80 | 0.688 [0.566, 0.788] | 0.000 [0.000, 0.057] | 5/6 |
| 90 | 0.562 [0.441, 0.677] | 0.000 [0.000, 0.057] | 3/6 |

Highest mean F1 in sweep A is at threshold 0.05 (F1 0.825 vs 0.759 at 0.35). Treat this as a hypothesis to confirm on the Phase 4 validation sessions, not as a tuned result.
