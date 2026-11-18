# EXP-6: Statistical robustness

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

## A. Training-seed variance (primary split, 20 seeds)

Only the model's random seed changes (XGBoost subsampling, SGD order, MLP init); data split fixed.

| Detector | F1 mean ± sd | Recall mean ± sd | FPR mean ± sd |
|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.825 ± 0.005 | 0.723 ± 0.007 | 0.032 ± 0.000 |
| Random forest | 0.918 ± 0.011 | 0.936 ± 0.011 | 0.106 ± 0.021 |
| Autoencoder (benign-only) | 0.783 ± 0.100 | 0.655 ± 0.117 | 0.004 ± 0.009 |

(The paper model's XGBoost uses colsample 0.3, so the seed changes which features each tree sees.)

## B. Split-to-split variance of the paper model (n = 100 grouped splits)

| Metric | mean | sd | 2.5 pct | 97.5 pct |
|---|---|---|---|---|
| F1 | 0.759 | 0.091 | 0.620 | 0.879 |
| Recall | 0.676 | 0.149 | 0.458 | 0.882 |
| FPR | 0.112 | 0.165 | 0.000 | 0.533 |

Per-class recall over splits:

| Class | mean | sd | min | splits with recall < 0.5 |
|---|---|---|---|---|
| scan | 0.580 | 0.094 | 0.455 | 7% |
| bruteforce | 1.000 | 0.000 | 1.000 | 0% |
| dos | 1.000 | 0.000 | 1.000 | 0% |
| beacon | 0.170 | 0.230 | 0.000 | 86% |

Pooling windows across repeated splits would count the same window many times, so no pooled CI is reported. Use the percentile intervals above (split variability) together with the Wilson CIs of the primary split (sampling variability within one split).

## C. Within-session vs cross-session (scan + benign only)

Same model trained on all Oct 16/19 data. Within-session numbers use the repeated splits restricted to scan and benign windows; cross-session uses Oct 3.

| Setting | scan recall | benign FPR |
|---|---|---|
| within session (repeated splits) | 0.580 ± 0.094 | 0.112 ± 0.165 |
| cross session (Oct 3) | 1.000 [0.701, 1.000] (9/9 runs) | 0.676 [0.515, 0.804] |

Oct 3 scans are `nmap -T4 -p 1-1000` (about 1 s each, one 5-s window per run) while Oct 16 scans are `-p 1-65535`; a gap here mixes session shift with attack-variant shift and cannot separate them.
