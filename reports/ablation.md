# Ablation: what each monitor adds to detection

Same binary detector (XGBoost+SGD, fused), held-out = last 30%% of each class.

| feature set | precision | recall | F1 | accuracy | false-pos rate |
|---|---|---|---|---|---|
| network (28) | 0.941 | 0.909 | 0.925 | 0.945 | 0.033 |
| network+syscall (39) | 0.948 | 0.830 | 0.885 | 0.920 | 0.027 |
| all 3 monitors (45) | 0.973 | 0.807 | 0.882 | 0.920 | 0.013 |

**Energy+syscall lift:** F1 0.925 -> 0.882 (+-0.043)

## Attacks the 3-monitor model catches that network-only misses

| attack class | windows recovered |
|---|---|
| beacon | 1 |

These are device-side-heavy windows (low packet rate, high CPU/syscalls) that a network-only detector ranks as benign - the contextual-fingerprint novelty.
