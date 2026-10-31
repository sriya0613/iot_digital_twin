#!/usr/bin/env python3
"""feedback_loop.py - the incremental-learning feedback arrow, demonstrated.

Scenario: a NEW attack variant appears that the deployed model was not trained on. As the
self-healing engine confirms detections, those windows are fed back into the incremental
model (online learn_one / partial_fit). We measure the incremental model's detection rate on
the new attack BEFORE any feedback vs AFTER feedback - with no full retrain. This is the
'Update Threat Database -> incremental model' loop closing in the architecture.

    python3 feedback_loop.py --dataset data/dataset_v3.jsonl --novel bruteforce --out reports/feedback_loop.md
"""
import argparse, json, os
import numpy as np
from sklearn.linear_model import SGDClassifier
from common import FEATURE_ORDER_V2

ATTACK = {"scan", "bruteforce", "dos", "beacon"}


def load(path):
    X, y, cls = [], [], []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line); f = r["features"]
        c = r.get("attack_class") or ""; lab = r.get("label")
        if c in ATTACK or lab == "malware":
            yy, cc = 1, (c if c in ATTACK else "attack")
        elif lab == "benign":
            yy, cc = 0, "benign"
        else:
            continue
        X.append([f.get(k, 0.0) for k in FEATURE_ORDER_V2]); y.append(yy); cls.append(cc)
    return np.array(X, float), np.array(y, int), np.array(cls, dtype=object)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset_v3.jsonl")
    ap.add_argument("--novel", default="bruteforce", help="the attack class held out as a new, unseen variant")
    ap.add_argument("--out", default="reports/feedback_loop.md")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    X, y, cls = load(a.dataset)
    novel = (cls == a.novel)
    if novel.sum() < 10:
        print("not enough '%s' windows" % a.novel); return

    # base model: trained on benign + every OTHER attack, but NEVER the novel class
    base_mask = (cls == "benign") | ((y == 1) & ~novel)
    Xb, yb = X[base_mask], y[base_mask]
    rng = np.random.RandomState(0)
    inc = SGDClassifier(loss="log_loss", alpha=1e-4, learning_rate="constant", eta0=0.05, random_state=0)
    w = np.where(yb == 1, (yb == 0).sum() / max(1, (yb == 1).sum()), 1.0)
    for _ in range(200):
        idx = rng.permutation(len(Xb))
        inc.partial_fit(Xb[idx], yb[idx], classes=[0, 1], sample_weight=w[idx])

    Xn = X[novel]; rng.shuffle(Xn)
    half = len(Xn) // 2
    feedback, test = Xn[:half], Xn[half:]
    detect = lambda M: float((inc.predict_proba(M)[:, 1] >= 0.5).mean())

    before = detect(test)
    # feedback loop: confirmed incidents (label=attack) streamed back into the incremental model
    for _ in range(20):
        inc.partial_fit(feedback, np.ones(len(feedback), int))
    after = detect(test)

    with open(a.out, "w") as f:
        f.write("# Feedback loop: incremental adaptation to a new attack (no retrain)\n\n")
        f.write("A '%s' attack is treated as a brand-new variant the model never trained on. "
                "The incremental model's detection of it is measured before any feedback, then after "
                "confirmed detections are streamed back (online partial_fit) - no full retrain.\n\n" % a.novel)
        f.write("| | detection rate on the new '%s' attack |\n|---|---|\n" % a.novel)
        f.write("| before feedback (never seen it) | %.0f%% |\n" % (100 * before))
        f.write("| after feedback loop (online updates) | %.0f%% |\n\n" % (100 * after))
        f.write("The incremental learner adapts to the new threat from confirmed detections alone, "
                "without retraining the whole model - the 'Update Threat Database -> incremental model' "
                "feedback arrow in the architecture.\n")
    print(open(a.out).read())


if __name__ == "__main__":
    main()
