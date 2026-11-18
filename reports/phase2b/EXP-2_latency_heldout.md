# EXP-2 — Detection latency with held-out models

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2b.py`; nothing copied from the paper.

Latency = end of the first flagged window − attack start (manifest), using the same window matching as `latency_fp.py` (windows overlapping the run, +5 s slack). Each attack run is timed only by models that did not train on it (100 grouped splits; each run is in the test part of ~30% of splits). Per run, the median over those splits is taken; the table summarises runs. A run counts as detected if detected in > 50% of its test splits. Pipeline and decision delays are not included (Phase 3 measures them live).

## fused ≥ 0.35 (alert)

| Class | runs detected | median | p95 | max |
|---|---|---|---|---|
| scan | 8/8 | 16.6 s | 17.5 s | 17.7 s |
| bruteforce | 4/4 | 2.7 s | 3.5 s | 3.6 s |
| dos | 7/7 | 2.7 s | 3.2 s | 3.2 s |
| beacon | 2/3 | 6.7 s | 8.5 s | 8.7 s |
| **all** | 21/22 | 3.6 s | 17.1 s | 17.7 s |

## risk ≥ 30 (rate-limit)

| Class | runs detected | median | p95 | max |
|---|---|---|---|---|
| scan | 8/8 | 9.5 s | 16.7 s | 17.0 s |
| bruteforce | 4/4 | 2.7 s | 3.5 s | 3.6 s |
| dos | 7/7 | 2.7 s | 3.2 s | 3.2 s |
| beacon | 2/3 | 6.7 s | 8.5 s | 8.7 s |
| **all** | 21/22 | 3.1 s | 16.1 s | 17.0 s |

## risk > 70 (quarantine)

| Class | runs detected | median | p95 | max |
|---|---|---|---|---|
| scan | 8/8 | 16.6 s | 17.5 s | 17.7 s |
| bruteforce | 4/4 | 2.7 s | 3.5 s | 3.6 s |
| dos | 7/7 | 2.8 s | 4.7 s | 5.4 s |
| beacon | 0/3 | — | — | — |
| **all** | 19/22 | 3.6 s | 17.1 s | 17.7 s |

The old `reports/latency_fp.md` (median 5.0 s, all 22 runs detected) used `models_v3_hybrid`, trained on these same runs; it is superseded by this table.
