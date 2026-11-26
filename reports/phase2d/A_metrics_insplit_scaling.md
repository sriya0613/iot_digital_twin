# Phase 2d — Metrics with in-split scaling, trivial baselines and equal-FPR comparison

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2d.py` with **min-max bounds refitted on the training runs of every split**.

100 grouped run-ID splits (same seeds as Phases 2-2c). Mean over splits; sd and percentiles in the JSON. Recall@FPR is read off each split's test ROC curve: it compares ranking quality at equal false-alarm rates and is **not** a threshold the live system could use.

| Detector | F1 | Recall | FPR | MCC | Bal. acc. | PR-AUC | ROC-AUC | Recall@FPR 0.05 | Recall@FPR 0.10 | scan | beacon |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Deployed recipe (XGB+SGD, aug, 45) | 0.754 | 0.676 | 0.128 | 0.544 | 0.774 | 0.945 | 0.910 | 0.725 | 0.769 | 0.596 | 0.164 |
| Deployed recipe, network 28 | 0.815 | 0.764 | 0.129 | 0.624 | 0.817 | 0.942 | 0.894 | 0.782 | 0.807 | 0.523 | 0.498 |
| XGB+SGD without scan augmentation (45) | 0.877 | 0.968 | 0.339 | 0.676 | 0.815 | 0.965 | 0.947 | 0.813 | 0.845 | 0.997 | 0.909 |
| XGB+SGD without augmentation, network 28 | 0.885 | 0.973 | 0.318 | 0.696 | 0.828 | 0.955 | 0.933 | 0.779 | 0.813 | 0.856 | 0.978 |
| Random forest (45) | 0.855 | 0.926 | 0.332 | 0.622 | 0.797 | 0.957 | 0.943 | 0.743 | 0.833 | 0.962 | 0.798 |
| Logistic regression (45) | 0.822 | 0.818 | 0.209 | 0.616 | 0.804 | 0.956 | 0.937 | 0.781 | 0.846 | 0.825 | 0.591 |
| Autoencoder, benign only (45) | 0.743 | 0.623 | 0.041 | 0.585 | 0.791 | 0.904 | 0.804 | 0.649 | 0.681 | 0.759 | 0.017 |
| KitNET-style, benign only (45) | 0.753 | 0.666 | 0.108 | 0.548 | 0.779 | 0.885 | 0.753 | 0.657 | 0.673 | 0.756 | 0.018 |
| Deployed recipe, OLD global scaling (45) | 0.759 | 0.676 | 0.112 | 0.560 | 0.782 | 0.944 | 0.907 | 0.724 | 0.770 | 0.580 | 0.170 |
| Trivial: flag every window | 0.748 | 1.000 | 1.000 | 0.000 | 0.500 | 0.603 | 0.500 | 0.000 | 0.000 | 1.000 | 1.000 |
| Trivial: random at training attack rate | 0.618 | 0.655 | 0.670 | -0.013 | 0.493 | 0.611 | 0.493 | 0.057 | 0.105 | 0.648 | 0.658 |

## Deployed recipe: false-positive rate across splits

median 0.046, mean 0.128, 90th percentile 0.359; FPR = 0 in 31% of splits. At one window every 5 s this is a median of 33 (mean 92) benign windows per hour flagged as malicious.

## Paired comparison with the deployed recipe (same splits, Wilcoxon signed-rank)

| Detector | ΔMCC (p) | ΔPR-AUC (p) | ΔRecall@FPR 0.05 (p) | ΔRecall@FPR 0.10 (p) | better/worse in PR-AUC |
|---|---|---|---|---|---|
| Deployed recipe, network 28 | +0.080 (1.67e-08) | -0.004 (0.00607) | +0.057 (8.07e-06) | +0.038 (0.00235) | 37% / 63% |
| XGB+SGD without scan augmentation (45) | +0.131 (4.96e-09) | +0.020 (2.78e-15) | +0.089 (2.37e-15) | +0.076 (6.09e-14) | 90% / 6% |
| XGB+SGD without augmentation, network 28 | +0.151 (1.93e-08) | +0.010 (8.15e-08) | +0.054 (1.48e-06) | +0.044 (3.59e-06) | 71% / 29% |
| Random forest (45) | +0.077 (1.7e-05) | +0.012 (1.02e-05) | +0.019 (0.00269) | +0.064 (3.55e-07) | 74% / 23% |
| Logistic regression (45) | +0.071 (6.04e-06) | +0.011 (0.00112) | +0.057 (3.65e-06) | +0.078 (1.09e-09) | 63% / 37% |
| Autoencoder, benign only (45) | +0.041 (0.0611) | -0.042 (2.87e-11) | -0.076 (2.84e-06) | -0.088 (2.72e-07) | 18% / 82% |
| KitNET-style, benign only (45) | +0.004 (0.77) | -0.060 (1.46e-17) | -0.068 (4.13e-08) | -0.095 (1.38e-08) | 6% / 94% |

Splits share most training runs, so they are not independent; p-values are descriptive, not a formal test across sessions.
