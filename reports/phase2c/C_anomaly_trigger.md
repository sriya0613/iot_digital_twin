# Phase 2c C — Anomaly score as an independent trigger

**Status**: PRELIMINARY — attacks from one session (Oct 16). Rules fixed in advance in `experiments/PHASE2C_PREREG.md` (committed before this run). Outer test parts never used for choices.

Deployed: act (rate-limit) when risk ≥ 30; the anomaly term alone can add at most 20, so it can never trigger. Variant: act when risk ≥ 30 OR anomaly ≥ 1.0 (reconstruction error above the 99th percentile of benign training windows).

## Repeated grouped splits (n = 100), action level

| Rule | recall | FPR | episodes acted on | beacon recall |
|---|---|---|---|---|
| risk ≥ 30 (deployed) | 0.707 ± 0.150 | 0.181 ± 0.197 | 0.955 | 0.226 |
| risk ≥ 30 OR anomaly ≥ 1 | 0.713 ± 0.149 | 0.227 ± 0.219 | 0.955 | 0.227 |

## Unseen attack class (class removed from training; primary split)

| Unseen class | deployed: recall / FPR / episodes | OR anomaly: recall / FPR / episodes |
|---|---|---|
| scan | 0.511 / 0.032 / 8 of 8 | 0.600 / 0.032 / 8 of 8 |
| bruteforce | 1.000 / 0.032 / 4 of 4 | 1.000 / 0.032 / 4 of 4 |
| dos | 1.000 / 0.032 / 7 of 7 | 1.000 / 0.032 / 7 of 7 |
| beacon | 0.000 / 0.016 / 0 of 3 | 0.028 / 0.016 / 2 of 3 |
