# Unknown-threat detection (the autoencoder / anomaly path)

The autoencoder is trained on BENIGN windows only. For each attack class we pretend it is
a brand-new, never-seen threat: we never train on it, then measure what fraction the anomaly
score flags above the benign threshold (99th-percentile of each feature's benign error).

| held-out (unseen) attack | detected by anomaly score | benign flagged (false alarms) |
|---|---|---|
| beacon | 0% (0/72 windows) | 8% |
| bruteforce | 99% (133/134 windows) | 8% |
| dos | 100% (34/34 windows) | 8% |
| scan | 78% (35/45 windows) | 8% |

The autoencoder never saw any attack in training, yet flags these windows purely because
they do not look like benign traffic - this is the 'unknown threat' half of the hybrid detector.
