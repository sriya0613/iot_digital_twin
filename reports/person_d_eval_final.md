# Person D evaluation (from threat_eval.db)

## Decisions

| | count |
|---|---|
| alerts processed | 814 (0 synthetic) |
| ignored | 341 |
| observe | 330 |
| held | 115 |
| rate_limit | 19 |
| quarantine | 9 |
| benign-labelled windows that were rate-limited or quarantined | 0 of 602 |

## Heals

| | value |
|---|---|
| heals | 9 |
| success rate | 8 / 9 (89%) |
| restore time, detector (real restore.sh) | – |
| restore time, our engine | median 101.94 s, min 9.89, max 378.95 (n=8) |
| verify: failed | 1 |
| verify: verified | 8 |

## Escalations and containment

| | value |
|---|---|
| escalations: hold | 1 |
| held right now | 1 |
| containment time (isolate rule added + verified) | median 0.12 s, min 0.06, max 0.19 (n=9) |
| containment steps verified on the switch | 43 / 43 |

## Processing delay

Alert written by the detector -> decision stored: median 0.19 s, min 0.03, max 59.63 (n=602)

## Not measurable from threat.db

- True false-positive rate and detection latency need the times an attack really ran (Person B's run_manifest.jsonl). The benign-label row above uses the detector's own label instead.
- Restore times of 'our engine' on a laptop come from tests/fake_restore.py and mean nothing; use a live run on the twin host.
