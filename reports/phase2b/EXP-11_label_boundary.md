# EXP-11 — Label-boundary analysis

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2b.py`; nothing copied from the paper.

A window gets the label of the run it overlaps (`stream/pipeline.Labeler`), even if only part of the 5 s is inside the run. 'Partial' = less than the full 5 s inside its run. Detection rate = share of test-split appearances in which the paper detector flagged the window (100 grouped splits).

| Class | windows | partial | detection rate, full windows | detection rate, partial windows |
|---|---|---|---|---|
| benign | 158 | 13 | 0.129 | 0.035 |
| scan | 45 | 15 | 0.610 | 0.498 |
| bruteforce | 134 | 8 | 1.000 | 1.000 |
| dos | 34 | 13 | 1.000 | 1.000 |
| beacon | 72 | 5 | 0.134 | 0.189 |

## Benign windows within 10 s after an attack run

| Benign windows | n | false-alarm rate |
|---|---|---|
| ≤ 10 s after an attack ended | 0 | — |
| all other benign | 158 | 0.121 |

If partial windows are detected much less often than full ones, part of the measured miss rate is a labelling artefact (a window with 1 s of attack and 4 s of idle is labelled attack). Phase 4 sessions keep a 15 s gap before each attack and benign traffic after it, so both effects can be measured on independent data.
