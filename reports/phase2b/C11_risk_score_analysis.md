# C11 — Blended risk score per class and the reinfection threshold

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2b.py`; nothing copied from the paper.

risk = 100·(0.5·conf + 0.2·anomaly + 0.3·severity·conf), as `HybridModel.assess()` (vectorised; a unit test checks it equals `assess()`). Values pooled over 100 grouped run-ID splits: each attack/benign window is scored only by models that did not train on its run. 'healing' = windows recorded while the twin was restored and rebooted (3 Oct 16 runs, never used for training). **Post-grace** = the last 60 s of each healing run: the engine ignores the device for 90 s after the restore ends and runs are labelled for 150 s after it, so only these windows reach the verifier (assumes the documented `--pad 150`; every healing run lasts ~218 s, consistent with it). An earlier draft of this analysis scored all healing windows; that overstates false reinfection and is kept only as a reference row.

## Risk distribution

| Class | windows×splits | median | p10 | p90 | ≥ 30 (act) | > 50 (strict) | > 70 (quarantine) | > 80 (reinfect) |
|---|---|---|---|---|---|---|---|---|
| benign | 5437 | 12 | 7 | 39 | 19.7% | 3.8% | 0.0% | 0.0% |
| scan | 1130 | 77 | 19 | 82 | 67.4% | 53.4% | 51.6% | 42.5% |
| bruteforce | 3368 | 90 | 88 | 90 | 100.0% | 100.0% | 99.4% | 96.6% |
| dos | 959 | 97 | 96 | 97 | 100.0% | 100.0% | 100.0% | 100.0% |
| beacon | 2699 | 14 | 6 | 36 | 18.1% | 1.0% | 0.0% | 0.0% |
| healing, post-grace (last 60 s) | 3600 | 14 | 11 | 35 | 19.4% | 0.1% | 0.0% | 0.0% |
| (healing, all windows incl. restore) | 13300 | 22 | 12 | 77 | 40.0% | 23.8% | 17.5% | 6.8% |

## Reinfection rule at run level: ≥ 2 consecutive windows above T

The healing engine flags reinfection when REINFECT_STREAK (2) consecutive post-grace windows exceed REINFECT_ABOVE (80). For each T: share of attack runs that would trip the rule (wanted) and share of restore/boot runs that would trip it on their post-grace windows (false reinfection). Runs × splits.

| T | scan | bruteforce | dos | beacon | benign runs | restore/boot, post-grace | (all restore/boot windows) |
|---|---|---|---|---|---|---|---|
| 30 | 100% | 100% | 100% | 34% | 22% | 23% | (100%) |
| 40 | 100% | 100% | 100% | 20% | 11% | 6% | (100%) |
| 50 | 100% | 100% | 100% | 3% | 5% | 0% | (100%) |
| 60 | 100% | 100% | 100% | 0% | 0% | 0% | (100%) |
| 65 | 100% | 100% | 100% | 0% | 0% | 0% | (100%) |
| 70 | 100% | 100% | 100% | 0% | 0% | 0% | (96%) |
| 75 | 100% | 100% | 100% | 0% | 0% | 0% | (74%) |
| 80 ← current | 100% | 100% | 100% | 0% | 0% | 0% | (27%) |
| 85 | 0% | 100% | 100% | 0% | 0% | 0% | (10%) |
| 90 | 0% | 14% | 100% | 0% | 0% | 0% | (0%) |

**Rule fixed before reading the table**: choose the lowest T at which no restore/boot run (post-grace) and at most 5% of benign runs trip the 2-in-a-row rule (a false reinfection triggers another restore). Result: **T = 50** (currently 80). At T = 50 the rule catches: scan 100%, bruteforce 100%, dos 100%, beacon 3%.

Caveats: (1) the recommendation depends on which windows the verifier sees. Counting all healing windows (including the restore and early boot) no T below 90 avoids false reinfection (last column), which is why the deployed engine has a 90 s grace period. The post-grace set rests on the documented 150 s pad; Phase 3 R1 (5 clean heals) records exact restore-end times and must confirm this before `REINFECT_ABOVE` is changed. (2) Only 3 restore/boot runs exist, all from one day. (3) Beacon reinfection stays unreliable at any T (EXP-6).

## Autoencoder anomaly score per class (EXP-10 detail)

anomaly = reconstruction error / 99th percentile of benign training error, clipped to [0, 1]. (The code comment in `threat_model_v3.py` said 95th; the code uses the 99th — comment fixed.)

| Class | median | p90 | share at 1.0 (≥ benign p99) |
|---|---|---|---|
| benign | 0.489 | 0.914 | 6.9% |
| scan | 1.000 | 1.000 | 62.7% |
| bruteforce | 1.000 | 1.000 | 81.9% |
| dos | 1.000 | 1.000 | 100.0% |
| beacon | 0.383 | 0.682 | 2.9% |
| healing, post-grace (last 60 s) | 0.633 | 1.000 | 12.2% |
| (healing, all windows incl. restore) | 0.805 | 1.000 | 43.0% |
