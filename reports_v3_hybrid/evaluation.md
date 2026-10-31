# Hybrid multi-class detector — evaluation

Held-out = last 30% of each class.

## Binary detection (attack vs normal)
precision 0.901 | recall 0.830 | F1 0.864 | false-positive rate 0.053 (fp=8 of 150 normal)

## Per-class (attack type)

| class | precision | recall | F1 |
|---|---|---|---|
| beacon | 1.000 | 1.000 | 1.000 |
| bruteforce | 1.000 | 1.000 | 1.000 |
| dos | 1.000 | 1.000 | 1.000 |
| scan | 1.000 | 1.000 | 1.000 |

## SHAP contribution by monitor (held-out attacks)
network 65.1% | syscall 7.2% | energy 27.7%
