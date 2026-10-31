#!/usr/bin/env python3
"""test_step9_twin_view.py - Twin View state logic + replay (no streamlit, no twin needed)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twin_view as tv

fails = 0
def check(name, cond):
    global fails; fails += not cond
    print("%s  %s" % ("ok " if cond else "FAIL", name))

up = {"emulator": True, "ping": True, "http": True, "on_bridge": True, "controller": True}
check("running twin -> up", tv.derive_state(up, risk=5) == "up")
check("dead twin -> down", tv.derive_state({"emulator": False, "ping": False}) == "down")
check("contained -> contained", tv.derive_state(up, risk=90, contained=True) == "contained")
check("rate-limited -> rate_limited", tv.derive_state(up, risk=50, rate_limited=True) == "rate_limited")
check("high risk still up -> healing", tv.derive_state(up, risk=95) == "healing")
check("held overrides all", tv.derive_state(up, risk=5, held=True) == "held")

recs = [{"type": "window", "risk_score": 5, "detector_action": "none"},
        {"type": "window", "risk_score": 90, "detector_action": "alert_only"},
        {"type": "window", "risk_score": 90, "detector_action": "restore_started"},
        {"type": "window", "risk_score": 50, "detector_action": "none"}]
f = [tv.replay_frame(recs, k) for k in range(4)]
def ds(k):
    c, r, cont, rl, hl = f[k]; return tv.derive_state(c, r, cont, rl, False, hl)
check("replay benign -> up", ds(0) == "up")
check("replay attack -> contained", f[1][2] and ds(1) == "contained")
check("replay heal frame -> healing", f[2][4] and ds(2) == "healing")
check("replay heal frame drops ping", f[2][0]["ping"] is False)
check("replay mid-band -> rate_limited", f[3][3] and ds(3) == "rate_limited")
check("flows_summary counts D-cookies", (lambda s: s["drop"] == 1 and s["allow"] == 1)(
    tv.flows_summary([{"cookie": 0xD0000001, "actions": []},
                      {"cookie": 0xD0000001, "actions": ["OUTPUT:NORMAL"]},
                      {"cookie": 0, "actions": []}])))
print("\n%s" % ("ALL TWIN VIEW TESTS PASSED" if not fails else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
