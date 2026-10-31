#!/usr/bin/env python3
"""latency_fp.py - detection latency and false-positive rate, from the recorded data + manifest.

For every attack run in run_manifest.jsonl, find the windows that fall inside it, score them
with the trained detector, and measure how long after the attack started the first MALICIOUS
window appears (detection latency). For the benign runs, measure how many windows are wrongly
flagged (false-positive rate). Uses the real recorded timestamps - no live run needed.

    python3 latency_fp.py --dataset data/dataset_v3.jsonl --manifest data/run_manifest.jsonl \
        --model-dir models_v3_hybrid --out reports/latency_fp.md
"""
import argparse, json, os
import numpy as np
from common import FEATURE_ORDER_V2

ATTACK = {"scan", "bruteforce", "dos", "beacon"}


def load_windows(path):
    W = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        W.append((r["window_start_epoch"], r["window_end_epoch"],
                  [r["features"].get(k, 0.0) for k in FEATURE_ORDER_V2]))
    return W


def load_model(model_dir):
    try:
        from threat_model_v3 import HybridModel
        m = HybridModel.load(model_dir)
        t_mal = m.core.cfg["t_malicious"]
        score = lambda X: m.core.threat_probability(np.asarray(X, float))
        return score, t_mal
    except Exception:
        from threat_model import ThreatModel
        m = ThreatModel.load(model_dir)
        return (lambda X: m.threat_probability(np.asarray(X, float))), m.cfg["t_malicious"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset_v3.jsonl")
    ap.add_argument("--manifest", default="data/run_manifest.jsonl")
    ap.add_argument("--model-dir", default="models_v3_hybrid")
    ap.add_argument("--out", default="reports/latency_fp.md")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)

    W = load_windows(a.dataset)
    runs = [json.loads(l) for l in open(a.manifest) if l.strip()]
    score, t_mal = load_model(a.model_dir)

    def windows_in(r):
        s, e = r["start_epoch"], r["stop_epoch"]
        return [(ws, we, f) for (ws, we, f) in W if we > s and ws < e + 5]   # overlap, +1 window slack

    lat = {}        # class -> [latencies]
    detected = {}   # class -> (found, total runs)
    for r in runs:
        if r.get("label") != "malware":
            continue
        cls = r.get("attack_class") or "scan"
        win = windows_in(r)
        if not win:
            continue                                   # this run's windows are not in the dataset - skip it
        detected.setdefault(cls, [0, 0]); detected[cls][1] += 1
        X = [f for (_, _, f) in win]
        p = score(X)
        hit = [i for i, pi in enumerate(p) if pi >= t_mal]
        if hit:
            detected[cls][0] += 1
            first = win[hit[0]]
            lat.setdefault(cls, []).append(max(0.0, first[1] - r["start_epoch"]))   # window_end - attack start

    # false-positive rate on benign runs
    fp = tot = 0
    for r in runs:
        if r.get("label") != "benign":
            continue
        win = windows_in(r)
        if not win:
            continue
        p = score([f for (_, _, f) in win])
        fp += int((p >= t_mal).sum()); tot += len(p)
    fpr = fp / tot if tot else 0.0

    all_lat = [x for v in lat.values() for x in v]
    with open(a.out, "w") as fo:
        fo.write("# Detection latency and false-positive rate\n\n")
        fo.write("Windows are matched to the recorded attack/benign runs by time; a window is a detection "
                 "when its fused probability >= %.2f (the malicious threshold).\n\n" % t_mal)
        fo.write("## Detection latency (attack start -> first malicious window)\n\n")
        fo.write("| attack class | runs detected | median latency | min | max |\n|---|---|---|---|---|\n")
        for c in sorted(lat):
            v = lat[c]; d = detected[c]
            fo.write("| %s | %d/%d | %.1f s | %.1f | %.1f |\n" % (c, d[0], d[1], np.median(v), min(v), max(v)))
        if all_lat:
            fo.write("| **overall** | | **%.1f s** | %.1f | %.1f |\n" % (np.median(all_lat), min(all_lat), max(all_lat)))
        fo.write("\n## False-positive rate (benign traffic)\n\n")
        fo.write("%d of %d benign windows flagged malicious = **%.1f%%** false-positive rate.\n" % (fp, tot, 100 * fpr))
    print(open(a.out).read())


if __name__ == "__main__":
    main()
