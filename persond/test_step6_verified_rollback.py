#!/usr/bin/env python3
import os
os.environ.setdefault("HEAL_GRACE","30")
os.environ.setdefault("HEAL_REINFECT_STREAK","1")
os.environ.setdefault("HEAL_REINFECT_ABOVE","70")
"""Test for step 6 (Graded, Verified Rollback). Run from the personD_handoff folder:
    python persond/test_step6_verified_rollback.py
Uses tests/fake_restore.py and temporary databases - nothing real is restored."""
import os
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from healing_engine import HealingEngine  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402

tmpdir = tempfile.mkdtemp()
LOG = os.path.join(tmpdir, "fake_restore.log")
os.environ["FAKE_RESTORE_LOG"] = LOG
quiet, real_stdout = open(os.devnull, "w"), sys.stdout


def restores():
    return len(open(LOG).readlines()) if os.path.exists(LOG) else 0


def new_engine(name):
    return HealingEngine(ThreatDatabase(os.path.join(tmpdir, name + ".db")))


def win(t, risk):
    label = "benign" if risk < 15 else "suspicious" if risk < 35 else "malicious"
    return {"alert_version": "1.0.0", "type": "window", "emitted_at_epoch": t + 5.1,
            "alert_id": "192.168.0.1-%.3f" % t, "window_start_epoch": t, "window_end_epoch": t + 5,
            "device_ip": "192.168.0.1", "threat_label": label, "threat_probability": risk / 100,
            "risk_score": risk, "explanation": [{"feature": "n_unique_dst_ports", "value": 1,
                                                 "impact": 3, "direction": "raises risk"}],
            "detector_action": "alert_only"}


def run(eng, *pairs):
    sys.stdout = quiet
    try:
        return [eng.handle(win(t, r)) for t, r in pairs]
    finally:
        sys.stdout = real_stdout


def verify_status(eng):
    return [r[0] for r in eng.db.rows("SELECT verify_status FROM heals ORDER BY id")]


# 1. heal, grace period, then 3 low windows -> verified
eng = new_engine("t1")
run(eng, (0, 99), (10, 99), (40, 2), (45, 1), (50, 3))      # 10 is inside grace -> ignored
assert verify_status(eng) == ["verified"], verify_status(eng)
print("ok  heal + 3 low windows after grace -> verified")

# 2. heal, one low window, then high again -> reinfected, and healed again
eng = new_engine("t2")
r = run(eng, (0, 99), (40, 2), (45, 99))
assert verify_status(eng) == ["reinfected", "pending"], verify_status(eng)
assert r[-1] == "restored", r
print("ok  high risk after the heal -> reinfected, reset again")

# 3. 3 heals within 10 min -> stop auto-reset, hold for a human; later alerts do not reset
eng = new_engine("t3")
before = restores()
r = run(eng, (0, 99), (100, 99), (200, 99), (300, 99), (400, 99))
assert r == ["restored", "restored", "restored_then_held", "held", "held"], r
assert restores() - before == 3, restores() - before
assert eng.db.held_reason("192.168.0.1") == "3 heals within 10 min"
print("ok  3 heals within 10 min -> held; next attacks are NOT reset")

# 4. a human clears the device -> auto-reset works again
assert eng.db.clear("192.168.0.1")
r = run(eng, (1000, 99))
assert r == ["restored"], r
print("ok  after --clear, the device is auto-reset again")

# 5. 3 heals spread over more than 10 min -> no escalation
eng = new_engine("t5")
r = run(eng, (0, 99), (400, 99), (800, 99))
assert r == ["restored"] * 3 and not eng.escalated, (r, eng.escalated)
print("ok  3 heals over 13 min -> not escalated")

# 6. failed reset -> held
os.environ["FAKE_RESTORE_EXIT"] = "1"
eng = new_engine("t6")
r = run(eng, (0, 99), (100, 99))
del os.environ["FAKE_RESTORE_EXIT"]
assert r == ["restore_failed", "held"], r
assert verify_status(eng) == ["failed"], verify_status(eng)
print("ok  failed reset -> stored as failed, device held")

# 7. no alerts for a long time after the heal -> unverified, and a much later attack is NOT reinfection
eng = new_engine("t7")
run(eng, (0, 99), (2000, 99))
assert verify_status(eng)[0] == "unverified", verify_status(eng)
print("ok  no alerts within 2 min after grace -> unverified (later attack counted as a new one)")

# 8. a threat.db from before step 6 is upgraded automatically
old = os.path.join(tmpdir, "old.db")
c = sqlite3.connect(old)
c.execute("CREATE TABLE heals (id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, ok INTEGER, exit_code TEXT, "
          "restore_seconds REAL, window_end_epoch REAL, emitted_at_epoch REAL, source TEXT, "
          "UNIQUE (device_ip, emitted_at_epoch))")
c.commit(); c.close()
run(HealingEngine(ThreatDatabase(old)), (0, 99))
print("ok  old threat.db upgraded with the verify_status column")

# 9. the --clear command
env = dict(os.environ, THREAT_DB=os.path.join(tmpdir, "t3.db"))
ThreatDatabase(env["THREAT_DB"]).hold("192.168.0.1", "test", 0)
out = subprocess.run([sys.executable, "persond/healing_engine.py", "--clear", "192.168.0.1"],
                     env=env, capture_output=True, text=True).stdout
assert "cleared 192.168.0.1" in out, out
assert ThreatDatabase(env["THREAT_DB"]).held_reason("192.168.0.1") is None
print("ok  python persond/healing_engine.py --clear 192.168.0.1 works")

print("\nSTEP 6 TESTS PASSED")
