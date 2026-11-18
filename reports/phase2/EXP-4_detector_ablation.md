# EXP-4: Detector ablation

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

## A. Components of the binary core (repeated grouped splits, n = 100)

| Detector | F1 mean ± sd [2.5, 97.5 pct] | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Episodes detected |
|---|---|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.759 ± 0.091 [0.620, 0.879] | 0.676 ± 0.149 | 0.112 ± 0.165 | 0.907 | 0.933 |
| fused XGB+SGD (no aug) | 0.874 ± 0.077 [0.717, 0.993] | 0.963 ± 0.051 | 0.338 ± 0.278 | 0.942 | 1.000 |
| XGBoost only (aug) | 0.764 ± 0.092 [0.621, 0.879] | 0.678 ± 0.147 | 0.104 ± 0.160 | 0.913 | 0.935 |
| SGD only (aug) | 0.760 ± 0.102 [0.624, 0.875] | 0.623 ± 0.130 | 0.000 ± 0.000 | 0.865 | 0.833 |

## B. What the 0.6/0.4 fusion at threshold 0.35 implies

Fused = 0.6·p_xgb + 0.4·p_sgd ≥ 0.35. If XGBoost gives 0, SGD alone must reach 0.875. If SGD gives 0, XGBoost alone must reach 0.583. So either model can raise an alert alone only when very confident; this matters for the feedback loop (EXP-9), which updates only the SGD part.

## C. Policy level: blended risk score → action (primary split)

risk = 100·(0.5·conf + 0.2·anomaly + 0.3·severity·conf); policy acts at risk ≥ 30 (rate-limit) and ≥ 70 (quarantine). Severity is only applied when the binary label is not benign.

| Decision | Recall | FPR | Episodes |
|---|---|---|---|
| label malicious (fused ≥ 0.35) | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 5/6 |
| risk ≥ 30 (any action) | 0.766 [0.649, 0.853] | 0.032 [0.009, 0.109] | 6/6 |
| risk ≥ 70 (quarantine) | 0.703 [0.582, 0.801] | 0.000 [0.000, 0.057] | 5/6 |
| risk ≥ 30 without anomaly term | 0.719 [0.599, 0.814] | 0.032 [0.009, 0.109] | 5/6 |

- Windows whose action (risk ≥ 30) changes when the anomaly term is removed: **3 of 127**.
- Attack windows the autoencoder flags (anomaly ≥ 1) but the fused score misses: **1**.
- Maximum risk from the anomaly term alone (conf = 0): 0.2 × 100 = **20 < 30**, so by construction the autoencoder can never trigger a containment action on its own. An attack the supervised core misses entirely (a true unknown threat) cannot be contained by the current risk formula.

