# Detection latency and false-positive rate

Windows are matched to the recorded attack/benign runs by time; a window is a detection when its fused probability >= 0.35 (the malicious threshold).

## Detection latency (attack start -> first malicious window)

| attack class | runs detected | median latency | min | max |
|---|---|---|---|---|
| beacon | 3/3 | 8.7 s | 4.6 | 13.3 |
| bruteforce | 4/4 | 2.7 s | 1.5 | 3.6 |
| dos | 7/7 | 2.8 s | 0.8 | 5.4 |
| scan | 8/8 | 16.6 s | 13.9 | 17.7 |
| **overall** | | **5.0 s** | 0.8 | 17.7 |

## False-positive rate (benign traffic)

2 of 172 benign windows flagged malicious = **1.2%** false-positive rate.
