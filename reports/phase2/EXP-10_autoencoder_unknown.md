# EXP-10: Autoencoder and unknown-threat detection (leave-one-class-out)

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

For each attack class C: every detector is trained on the primary split's training runs **with all C windows removed**, then tested on all C windows (as an unseen attack) plus the benign test runs. The benign-only detectors never see attack labels, so for them this equals their normal operation.

| Detector | recall on unseen scan | recall on unseen bruteforce | recall on unseen dos | recall on unseen beacon | benign FPR (mean) |
|---|---|---|---|---|---|
| paper: fused XGB+SGD (aug) | 0.511 [0.370, 0.650] (8/8 ep) | 1.000 [0.972, 1.000] (4/4 ep) | 1.000 [0.898, 1.000] (7/7 ep) | 0.000 [0.000, 0.051] (0/3 ep) | 0.024 |
| Random forest | 0.511 [0.370, 0.650] (8/8 ep) | 0.381 [0.303, 0.465] (4/4 ep) | 1.000 [0.898, 1.000] (7/7 ep) | 0.000 [0.000, 0.051] (0/3 ep) | 0.075 |
| Logistic regression | 0.667 [0.521, 0.786] (8/8 ep) | 0.000 [0.000, 0.028] (0/4 ep) | 1.000 [0.898, 1.000] (7/7 ep) | 0.000 [0.000, 0.051] (0/3 ep) | 0.048 |
| Autoencoder (benign-only) | 0.600 [0.455, 0.730] (8/8 ep) | 1.000 [0.972, 1.000] (4/4 ep) | 1.000 [0.898, 1.000] (7/7 ep) | 0.028 [0.008, 0.096] (2/3 ep) | 0.016 |
| Isolation forest (benign-only) | 0.467 [0.329, 0.609] (8/8 ep) | 1.000 [0.972, 1.000] (4/4 ep) | 1.000 [0.898, 1.000] (7/7 ep) | 0.000 [0.000, 0.051] (0/3 ep) | 0.016 |

## Would the autoencoder help if it could trigger on its own?

Rule tested: alert if fused ≥ 0.35 **or** anomaly ≥ 1.0 (the deployed system does NOT do this; see EXP-4 C).

| Unseen class | fused only: recall / FPR | fused OR anomaly: recall / FPR |
|---|---|---|
| scan | 0.511 / 0.016 | 0.600 / 0.032 |
| bruteforce | 1.000 / 0.032 | 1.000 / 0.032 |
| dos | 1.000 / 0.032 | 1.000 / 0.032 |
| beacon | 0.000 / 0.016 | 0.028 / 0.016 |

Caveat: the benign test set is 2 runs (63 windows), so FPR resolution is about 1.6% per window and the Wilson intervals are wide. The 99th-percentile threshold implies ~1% FPR on benign data like the training benign.
