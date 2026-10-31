#!/usr/bin/env python3
"""Test for step 1. Run from the personD_handoff folder:  python persond/test_step1_reader.py"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402

# 1. every shipped sample file reads with zero bad lines
for path in sorted(glob.glob("samples/*.jsonl")):
    bad = []
    recs = list(read_alerts(open(path), on_bad=lambda n, w: bad.append((n, w))))
    raw = sum(1 for l in open(path) if l.strip())
    assert not bad, "%s has bad lines: %s" % (path, bad)
    assert len(recs) == raw, path
    print("ok  %-55s %3d records" % (path, len(recs)))

# 2. broken input is skipped, not crashed on
good = open("samples/SYNTHETIC_risk_ladder.jsonl").readline()
broken = json.loads(good); broken["risk_score"] = 150            # out of range
missing = json.loads(good); del missing["alert_id"]              # required field gone
lines = [good, "this is not json\n", json.dumps(broken), json.dumps(missing), "[1,2]", "", good]
bad = []
recs = list(read_alerts(lines, on_bad=lambda n, w: bad.append(n)))
assert len(recs) == 2, recs
assert bad == [2, 3, 4, 5], bad
print("ok  broken lines skipped:", bad)

print("\nSTEP 1 TESTS PASSED")
