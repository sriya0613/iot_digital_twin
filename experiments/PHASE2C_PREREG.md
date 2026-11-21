# Phase 2c — pre-declared improvements (written and committed BEFORE running)

Data: dataset_v3 (Oct 16 + Oct 19). All attacks from one session, so every result stays PRELIMINARY.
Evaluation: the same grouped run-ID splits as Phase 2 (outer splits, seeds 0..N-1). The outer test part is
never used to choose anything.

## A. Pipeline selection by nested grouped evaluation

Candidates (12): model ∈ {paper fused XGB+SGD with scan augmentation, fused without augmentation,
random forest, logistic regression} × features ∈ {all 45, network 28, network + syscall 39}.

Selection rule, fixed now: inside each outer training part, run 4 inner grouped run-ID splits; pick the
candidate with the highest mean inner F1 (ties: lower mean inner FPR, then the simpler feature set).
Fit it on the whole outer training part and score the outer test part once.

Reported: the outer distribution (mean ± sd, 2.5–97.5 pct) of F1, recall, FPR, per-class recall for
"selected pipeline", next to the paper model on the same splits; how often each candidate was selected.
The claim allowed is "a pipeline chosen this way scores X on held-out runs", never "candidate C is best"
from the outer numbers.

## B. Cross-window (temporal) features — a declared variant

Motivation: beacon recall 0.17; one request per window is invisible to per-window features.
Features, causal (current window and the past only, in recording order; history resets after a gap > 30 s):
for f in {n_http, pkt_count, n_unique_dst_ports, frac_syn}: mean and max over the last 6 windows (30 s);
http_active_frac_12 = share of the last 12 windows (60 s) with n_http > 0;
http_gap_std_12 = std of the gaps between http-active windows in the last 12 windows (0 if < 3 active).
Compared on the same outer splits: paper model on all 45 vs all 45 + temporal; network 28 vs network 28 +
temporal. Reported separately as a variant (schema 2.0.0 is unchanged; the live detector would need the
same rolling computation).

## C. Anomaly score as an independent trigger

Policy variant: act (rate-limit) if risk ≥ 30 OR anomaly ≥ 1.0 (99th pct of benign training error).
Compared with the deployed rule (risk ≥ 30) on the outer splits and in leave-one-class-out (unseen class):
recall, FPR, episodes.

## Fixed in advance

Thresholds as deployed (0.35 for the fused score, 0.5 for other classifiers, risk 30). No outer-test
information is used for any choice. Whatever the outcome — better, worse or unchanged — it is reported.
