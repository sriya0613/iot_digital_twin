# Person D evaluation (from /home/vboxuser/p3/phase3.db)

## Decisions

| | count |
|---|---|
| alerts processed | 231 (0 synthetic) |
| held | 90 |
| ignored | 80 |
| observe | 57 |
| quarantine | 3 |
| rate_limit | 1 |
| benign-labelled windows that were rate-limited or quarantined | 0 of 169 |

## Heals

| | value |
|---|---|
| heals | 3 |
| success rate | 3 / 3 (100%) |
| restore time, detector (real restore.sh) | – |
| restore time, our engine | median 108.95 s, min 106.80, max 109.51 (n=3) |
| verify: pending | 1 |
| verify: verified | 2 |

## Escalations and containment

| | value |
|---|---|
| escalations: hold | 1 |
| held right now | 1 |
| containment time (isolate rule added + verified) | median 0.08 s, min 0.08, max 0.08 (n=3) |
| containment steps verified on the switch | 7 / 7 |

## Processing delay

Alert written by the detector -> decision stored: median 0.18 s, min 0.04, max 59.25 (n=174)

## Not measurable from threat.db

- True false-positive rate and detection latency need the times an attack really ran (Person B's run_manifest.jsonl). The benign-label row above uses the detector's own label instead.
- Restore times of 'our engine' on a laptop come from tests/fake_restore.py and mean nothing; use a live run on the twin host.
