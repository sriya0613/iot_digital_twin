#!/usr/bin/env python3
"""unknown_threat.py - does the anomaly path catch an attack it was never trained on?

Holds ONE attack class completely out of supervised training, trains the autoencoder on
benign windows only, then checks whether the held-out (unseen) attack is still flagged by
the autoencoder's reconstruction error. This validates the 'hybrid / unknown-threat' claim:
the supervised model can only catch what it has seen; the anomaly detector catches novelty.

    python3 unknown_threat.py --dataset data/dataset_v3.jsonl --out reports/unknown_threat.md
"""
import argparse, json, os
import numpy as np
from sklearn.neural_network import MLPRegressor
from common import FEATURE_ORDER_V2

ATTACK = {"scan", "bruteforce", "dos", "beacon"}


def load(path):
    """benign = ONLY label 'benign'. Attacks = their class. Healing/boot and unlabeled windows are
    dropped: boot traffic has high CPU/energy and would pollute the benign baseline the AE learns."""
    X, cls = [], []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line); f = r["features"]
        c = r.get("attack_class") or ""
        lab = r.get("label")
        if c in ATTACK or lab == "malware":
            kind = c if c in ATTACK else "attack"
        elif lab == "benign":
            kind = "benign"
        else:
            continue                                  # healing / unlabeled -> not a clean benign baseline
        X.append([f.get(k, 0.0) for k in FEATURE_ORDER_V2]); cls.append(kind)
    return np.array(X, float), np.array(cls, dtype=object)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset_v3.jsonl")
    ap.add_argument("--out", default="reports/unknown_threat.md")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    X, cls = load(a.dataset)
    classes = [c for c in ATTACK if (cls == c).sum() >= 5]

    lines = ["# Unknown-threat detection (the autoencoder / anomaly path)\n",
             "The autoencoder is trained on BENIGN windows only. For each attack class we pretend it is",
             "a brand-new, never-seen threat: we never train on it, then measure what fraction the anomaly",
             "score flags above the benign threshold (99th-percentile of each feature's benign error).\n",
             "| held-out (unseen) attack | detected by anomaly score | benign flagged (false alarms) |",
             "|---|---|---|"]
    ben = X[cls == "benign"]
    # split benign: train the AE on 70%, set threshold from it, test false alarms on 30%
    rng = np.random.RandomState(0); bi = rng.permutation(len(ben))
    tr_b, te_b = ben[bi[:int(.7 * len(ben))]], ben[bi[int(.7 * len(ben)):]]
    h = max(2, X.shape[1] // 3)
    ae = MLPRegressor(hidden_layer_sizes=(h,), activation="relu", solver="adam", max_iter=800, random_state=0)
    ae.fit(tr_b, tr_b)
    # per-feature reconstruction error, standardised by each feature's benign spread, then take the
    # MOST abnormal feature in the window. This catches attacks that deviate in only a few features
    # (e.g. brute-force: high CPU/energy, normal packet rate) which a mean-error score averages away.
    base = tr_b - ae.predict(tr_b)
    sd = base.std(axis=0) + 1e-6
    err = lambda M: np.max(np.abs(M - ae.predict(M)) / sd, axis=1)
    thr = float(np.percentile(err(tr_b), 99))
    fa = float((err(te_b) > thr).mean())
    for c in sorted(classes):
        atk = X[cls == c]
        det = float((err(atk) > thr).mean())
        lines.append("| %s | %.0f%% (%d/%d windows) | %.0f%% |" % (c, 100 * det, int(det * len(atk)), len(atk), 100 * fa))
    lines.append("\nThe autoencoder never saw any attack in training, yet flags these windows purely because")
    lines.append("they do not look like benign traffic - this is the 'unknown threat' half of the hybrid detector.")
    open(a.out, "w").write("\n".join(lines) + "\n")
    print(open(a.out).read())


if __name__ == "__main__":
    main()
