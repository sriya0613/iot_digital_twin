#!/usr/bin/env python3
import os
os.environ.setdefault("HEAL_GRACE","30")
os.environ.setdefault("HEAL_REINFECT_STREAK","1")
os.environ.setdefault("HEAL_REINFECT_ABOVE","70")
"""Test for step 4. Run from the personD_handoff folder:  python persond/test_step4_healing.py
Uses tests/fake_restore.py and a temporary database - nothing real is restored."""
import os
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402
from healing_engine import HealingEngine  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402

tmpdir = tempfile.mkdtemp()
LOG = os.path.join(tmpdir, "fake_restore.log")
os.environ["FAKE_RESTORE_LOG"] = LOG          # fake_restore.py writes one line per call here


def restores():
    return len(open(LOG).readlines()) if os.path.exists(LOG) else 0


def new_engine(name):
    return HealingEngine(ThreatDatabase(os.path.join(tmpdir, name + ".db")))


def win(t, risk, action="alert_only"):
    """A made-up window alert starting at time t."""
    label = "benign" if risk < 15 else "suspicious" if risk < 35 else "malicious"
    return {"alert_version": "1.0.0", "type": "window", "emitted_at_epoch": t + 5.1,
            "alert_id": "192.168.0.1-%.3f" % t, "window_start_epoch": t, "window_end_epoch": t + 5,
            "device_ip": "192.168.0.1", "threat_label": label, "threat_probability": risk / 100,
            "risk_score": risk, "explanation": [{"feature": "n_unique_dst_ports", "value": 1,
                                                 "impact": 3, "direction": "raises risk"}],
            "detector_action": action}


quiet = open(os.devnull, "w")
real_stdout = sys.stdout

# 1. a long attack: only ONE restore, the rest ignored; after the grace period a new attack restores again
sys.stdout = quiet
eng = new_engine("t1")
results = [eng.handle(win(t, 99)) for t in (0, 5, 10, 15, 20, 25, 30)]   # restore at window 0 ends at 5 -> ignore until ~35 (+ restore time)
results.append(eng.handle(win(40, 2)))                                   # after grace: observed normally
results.append(eng.handle(win(45, 99)))                                  # new attack -> second restore
sys.stdout = real_stdout
assert results[0] == "restored", results
assert results[1:7] == ["ignored"] * 6, results
assert results[7] == "observe" and results[8] == "restored", results
assert restores() == 2, restores()
print("ok  long attack -> 1 restore, 6 alerts ignored, next attack after grace -> restore again")

# 2. a failed restore escalates
os.environ["FAKE_RESTORE_EXIT"] = "1"
sys.stdout = quiet
eng = new_engine("t2")
r = eng.handle(win(0, 99))
sys.stdout = real_stdout
del os.environ["FAKE_RESTORE_EXIT"]
assert r == "restore_failed" and eng.escalated, (r, eng.escalated)
assert eng.db.rows("SELECT ok FROM heals")[0][0] == 0
print("ok  failed restore -> stored ok=False and escalated")

# 3. third restore of one device within 10 minutes escalates
sys.stdout = quiet
eng = new_engine("t3")
for t in (0, 100, 200):
    eng.handle(win(t, 99))
sys.stdout = real_stdout
assert [x[1] for x in eng.escalated] == ["3 heals within 10 min"], eng.escalated
print("ok  3rd restore of the same device within 10 min -> escalated")

# 4. rate-limit band never restores
before = restores()
sys.stdout = quiet
eng = new_engine("t4")
assert eng.handle(win(0, 50)) == "rate_limit"
sys.stdout = real_stdout
assert restores() == before
print("ok  risk 50 -> rate_limit, no restore")

# 5. a real mode-A recording: the detector already restored, we must NOT restore again
before = restores()
sys.stdout = quiet
eng = new_engine("t5")
c = Counter(eng.handle(a) for a in read_alerts(open("samples/alerts_three_monitor_clean_run.jsonl")))
sys.stdout = real_stdout
assert restores() == before, "restored a device the detector was already restoring"
assert c["left_to_detector"] == 1 and c["detector_heal"] == 1, c
print("ok  clean_run recording: left the restore to the detector, no double restore", dict(c))

# 6. every action is in the database
assert eng.db.count("actions") == eng.db.count("alerts")
print("ok  every alert has an action in the database")

print("\nSTEP 4 TESTS PASSED")
