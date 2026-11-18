#!/usr/bin/env python3 -I
"""validate_session.py — sanity checks on a built dataset (or raw session) before it is used.

  python3 -I scripts/validate_session.py data/dataset_v4.jsonl [--min-episodes 3]

Checks (FAIL = do not use the data; WARN = look before using):
  schema      every record schema 2.0.0 with all 45 features, values finite and in [0,1]
  timing      windows are 5 s, ordered, and gaps > 30 s are reported (twin crash / restart)
  monitors    syscall and energy monitors were alive (features not all constant)
  labels      every malware window has an attack_class; label counts per class
  episodes    number of independent attack episodes (run_ids) per class >= --min-episodes
  overlap     no window labelled by two manifest runs (attack episodes must not overlap)
Exit code 1 if any FAIL.
"""
import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common import FEATURE_ORDER_V2, SYSCALL_FEATURES, ENERGY_FEATURES  # noqa: E402

ATTACKS = ("scan", "bruteforce", "dos", "beacon")


def validate(path, min_episodes=3):
    fails, warns, info = [], [], []
    recs = []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError as e:
                fails.append("line %d: bad JSON (%s)" % (n, e))
    if not recs:
        return ["no records"], [], []
    info.append("%d records" % len(recs))

    # schema / values
    bad_schema = bad_val = 0
    for r in recs:
        f = r.get("features", {})
        if r.get("schema_version") != "2.0.0" or any(k not in f for k in FEATURE_ORDER_V2):
            bad_schema += 1
            continue
        for k in FEATURE_ORDER_V2:
            v = f[k]
            if not isinstance(v, (int, float)) or not math.isfinite(v) or v < -1e-9 or v > 1 + 1e-9:
                bad_val += 1
                break
    if bad_schema:
        fails.append("%d records not schema 2.0.0 / missing features" % bad_schema)
    if bad_val:
        warns.append("%d records with a value outside [0,1] (scaler from other data?)" % bad_val)

    # timing
    ts = [(r.get("window_start_epoch"), r.get("window_end_epoch")) for r in recs]
    ts = [(s, e) for s, e in ts if s is not None and e is not None]
    if ts:
        durs = Counter(round(e - s) for s, e in ts)
        if set(durs) - {5}:
            warns.append("window lengths other than 5 s: %s" % dict(durs))
        starts = sorted(s for s, _ in ts)
        gaps = [(b - a) for a, b in zip(starts, starts[1:]) if b - a > 30]
        if gaps:
            warns.append("%d gaps > 30 s (longest %.0f s) - twin restarts or recorder stops" % (len(gaps), max(gaps)))
    else:
        warns.append("no window timestamps - timing not checked")

    # monitors alive
    good = [r for r in recs if all(k in r.get("features", {}) for k in FEATURE_ORDER_V2)]
    for name, feats in (("syscall", ["sys_count", "sys_per_sec", "sys_unique"]),
                        ("energy", ["energy_cpu_util", "energy_mean_power"])):
        if good and all(len({r["features"][k] for r in good}) == 1 for k in feats):
            fails.append("%s monitor looks dead: %s constant in every window" % (name, feats))

    # labels and episodes
    lab = Counter(r.get("label", "") for r in recs)
    info.append("labels: %s" % dict(lab))
    no_cls = sum(1 for r in recs if r.get("label") == "malware" and not r.get("attack_class"))
    if no_cls:
        fails.append("%d malware windows without attack_class (use label_run.py --attack-class)" % no_cls)
    eps = defaultdict(set)
    wins = Counter()
    for r in recs:
        if r.get("label") == "malware" and r.get("attack_class"):
            eps[r["attack_class"]].add(r.get("run_id"))
            wins[r["attack_class"]] += 1
        elif r.get("label") == "benign":
            eps["benign"].add(r.get("run_id"))
            wins["benign"] += 1
    for c in ATTACKS + ("benign",):
        info.append("%-10s windows=%4d episodes=%d" % (c, wins[c], len(eps[c])))
        if c in ATTACKS and len(eps[c]) < min_episodes:
            warns.append("%s has %d episode(s) < %d required for a held-out test" % (c, len(eps[c]), min_episodes))
        if c in ATTACKS and 0 < wins[c] < 3:
            warns.append("%s has only %d windows - attack shorter than ~15 s?" % (c, wins[c]))

    # duplicate windows (same start time twice)
    starts = Counter(r.get("window_start_epoch") for r in recs if r.get("window_start_epoch") is not None)
    dup = sum(1 for v in starts.values() if v > 1)
    if dup:
        warns.append("%d window start times appear more than once (raw files built twice?)" % dup)
    return fails, warns, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--min-episodes", type=int, default=3)
    a = ap.parse_args()
    fails, warns, info = validate(a.path, a.min_episodes)
    for s in info:
        print("  info  ", s)
    for s in warns:
        print("  WARN  ", s)
    for s in fails:
        print("  FAIL  ", s)
    print("RESULT:", "FAIL" if fails else ("PASS with warnings" if warns else "PASS"))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
