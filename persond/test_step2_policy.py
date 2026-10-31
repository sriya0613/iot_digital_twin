#!/usr/bin/env python3
"""Test for step 2. Run from the personD_handoff folder:  python persond/test_step2_policy.py"""
import glob
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402
from policy import decide, OBSERVE, RATE_LIMIT, QUARANTINE  # noqa: E402


def window(risk):
    return {"type": "window", "risk_score": risk, "explanation": [{"feature": "pkt_count"}]}


# 1. the band edges
cases = {0: OBSERVE, 29: OBSERVE, 30: RATE_LIMIT, 50: RATE_LIMIT, 70: RATE_LIMIT, 71: QUARANTINE, 100: QUARANTINE}
for risk, want in cases.items():
    got, _ = decide(window(risk))
    assert got == want, "risk %d: got %s, want %s" % (risk, got, want)
print("ok  band edges:", cases)

# 2. heal records are not turned into actions
assert decide({"type": "heal", "ok": True, "restore_seconds": 60})[0] is None
print("ok  heal records give no action")

# 3. the synthetic ladder hits all three bands
c = Counter(decide(a)[0] for a in read_alerts(open("samples/SYNTHETIC_risk_ladder.jsonl")))
assert c[OBSERVE] and c[RATE_LIMIT] and c[QUARANTINE], c
print("ok  SYNTHETIC_risk_ladder:", dict(c))

# 4. every real recording: each malicious window is quarantined, each benign one observed
for path in sorted(glob.glob("samples/alerts_*.jsonl")):
    for a in read_alerts(open(path)):
        if a["type"] != "window":
            continue
        action = decide(a)[0]
        if a["threat_label"] == "malicious":
            assert action == QUARANTINE, (path, a["alert_id"], a["risk_score"])
        if a["threat_label"] == "benign":
            assert action == OBSERVE, (path, a["alert_id"], a["risk_score"])
    print("ok  %s" % path)

print("\nSTEP 2 TESTS PASSED")
