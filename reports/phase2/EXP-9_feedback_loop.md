# EXP-9: Feedback loop with an unseen attack class

**Status**: PRELIMINARY — training attacks all come from one session (Oct 16). Measured by `experiments/run_phase2.py`; nothing copied from the paper.

Protocol, per attack class C: train the paper's binary core with **every C window removed** (benign and other classes use the primary split's training runs). C's runs are sorted by time; the first run is the 'feedback' episode, the rest are the test episodes. Then update the incremental SGD model on the feedback episode, one window at a time, in two ways:

- **confirmed**: analyst-confirmed label 1 for each window (`partial_fit`, what HybridModel.online_update does with a confirmed label);
- **self-training**: the deployed rule `ThreatModel.online_update` (pseudo-label only when fused ≤ 0.05 or ≥ 0.95).

XGBoost is never updated (as in the code). Test = remaining C runs + benign test runs of the primary split.

| Unseen class | test C windows / runs | recall before | after self-training (updates used) | after confirmed | FPR before | FPR after confirmed |
|---|---|---|---|---|---|---|
| scan | 39 / 7 | 0.513 | 0.513 (5/6) | 0.513 | 0.016 | 0.016 |
| bruteforce | 87 / 3 | 1.000 | 1.000 (0/47) | 1.000 | 0.032 | 0.095 |
| dos | 29 / 6 | 1.000 | 1.000 (4/5) | 1.000 | 0.032 | 0.032 |
| beacon | 25 / 2 | 0.000 | 0.000 (46/47) | 0.680 | 0.016 | 0.508 |

Feedback-episode sizes: scan 6 windows, bruteforce 47 windows, dos 5 windows, beacon 47 windows.

Reading guide: 'before' is the unseen-class detection rate of the supervised core. Self-training can only help if some novel windows already score ≥ 0.95; otherwise it makes zero updates. Confirmed updates move only the SGD part, which carries 40% of the fused score (EXP-4 B).
