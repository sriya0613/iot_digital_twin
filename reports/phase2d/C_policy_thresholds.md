# Phase 2d — Policy action per class and threshold sensitivity

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2d.py` with **min-max bounds refitted on the training runs of every split**.

Full HybridModel risk (confidence, anomaly, severity), as in `assess()`, for every held-out window over 100 splits. 'Without anomaly' recomputes the same risk with the anomaly term set to 0, to show how much quarantine depends on it (review F5).

## Share of held-out windows

| Class | windows | ≥ 30 (act) | > 50 | > 60 | > 70 (deployed θ) | > 80 | > 70 without anomaly |
|---|---|---|---|---|---|---|---|
| benign | 5437 | 17.2% | 1.9% | 0.0% | 0.0% | 0.0% | 0.0% |
| scan | 1130 | 73.7% | 52.7% | 51.9% | 51.6% | 43.7% | 0.0% |
| bruteforce | 3368 | 100.0% | 100.0% | 99.8% | 98.4% | 96.2% | 44.3% |
| dos | 959 | 100.0% | 100.0% | 100.0% | 100.0% | 99.7% | 95.7% |
| beacon | 2699 | 11.0% | 0.3% | 0.0% | 0.0% | 0.0% | 0.0% |

## Share of held-out runs with at least one window in the band (run-level action)

| Class | run tests | any action (≥ 30) | any > 50 | any > 60 | any > 70 | any > 80 | any > 70 without anomaly |
|---|---|---|---|---|---|---|---|
| benign | 300 | 36.3% | 9.0% | 0.7% | 0.0% | 0.0% | 0.0% |
| scan | 200 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| bruteforce | 100 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| dos | 200 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| beacon | 100 | 54.0% | 2.0% | 0.0% | 0.0% | 0.0% | 0.0% |

For benign runs, 'any > θ' is the share of benign runs that would have caused at least one restore.
