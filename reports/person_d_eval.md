# Person D evaluation (from threat.db)

## Decisions

| | count |
|---|---|
| alerts processed | 292 (0 synthetic) |
| observe | 171 |
| ignored | 62 |
| held | 51 |
| rate_limit | 4 |
| quarantine | 4 |
| benign-labelled windows that were rate-limited or quarantined | 0 of 272 |

## Heals

| | value |
|---|---|
| heals | 4 |
| success rate | 3 / 4 (75%) |
| restore time, detector (real restore.sh) | – |
| restore time, our engine | median 70.36 s, min 68.97, max 70.64 (n=3) |
| verify: failed | 1 |
| verify: verified | 3 |

## Escalations and containment

| | value |
|---|---|
| escalations: hold | 1 |
| held right now | 1 |
| containment time (isolate rule added + verified) | median 0.11 s, min 0.02, max 0.29 (n=4) |
| containment steps verified on the switch | 13 / 13 |

## Processing delay

Alert written by the detector -> decision stored: median 0.17 s, min 0.03, max 59.65 (n=246)

## Not measurable from threat.db

- True false-positive rate and detection latency need the times an attack really ran (Person B's run_manifest.jsonl). The benign-label row above uses the detector's own label instead.
- Restore times of 'our engine' on a laptop come from tests/fake_restore.py and mean nothing; use a live run on the twin host.
