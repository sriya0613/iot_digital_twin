# C4 — KitNET-style baseline (benign-only)

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2b.py`; nothing copied from the paper.

Kitsune works on per-packet statistics; this repo only has 5-s window features, so this is a **KitNET-style** ensemble on window features (feature groups by correlation, ≤ 5 features each, one autoencoder per group, an output autoencoder), trained on benign training windows only, threshold = 99th percentile of benign training score — the same rule as the other benign-only detectors. 100 grouped run-ID splits.

| Detector | F1 mean ± sd | Recall mean ± sd | FPR mean ± sd | ROC-AUC | Oct 3 FPR | Oct 3 scan recall |
|---|---|---|---|---|---|---|
| KitNET-style (benign-only) | 0.751 ± 0.099 | 0.664 ± 0.141 | 0.111 ± 0.119 | 0.755 | 0.730 | 1.000 |
| Autoencoder (benign-only) | 0.692 ± 0.135 | 0.567 ± 0.162 | 0.069 ± 0.138 | 0.795 | 0.216 | 1.000 |
| Isolation forest (benign-only) | 0.635 ± 0.196 | 0.502 ± 0.205 | 0.019 ± 0.046 | 0.757 | 0.162 | 0.778 |
| paper: fused XGB+SGD (aug) | 0.759 ± 0.091 | 0.676 ± 0.149 | 0.112 ± 0.165 | 0.907 | 0.676 | 1.000 |

Per-class recall (mean over splits):

| Detector | scan | bruteforce | dos | beacon |
|---|---|---|---|---|
| KitNET-style (benign-only) | 0.750 | 1.000 | 1.000 | 0.015 |
| Autoencoder (benign-only) | 0.627 | 0.813 | 1.000 | 0.019 |
| Isolation forest (benign-only) | 0.476 | 0.743 | 0.962 | 0.004 |
| paper: fused XGB+SGD (aug) | 0.580 | 1.000 | 1.000 | 0.170 |
