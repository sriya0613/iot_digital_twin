#!/usr/bin/env python3
"""Test for step 8: escalation log, policy feedback, rate-limit escalation, containment through a
fake Ryu, health records, indicators. Run from the personD_handoff folder:
    python persond/test_step8_escalation_containment.py
Uses tests/fake_restore.py, persond/fake_ryu.py and temporary databases - nothing real is touched."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_ryu  # noqa: E402
from containment import Containment  # noqa: E402
from healing_engine import HealingEngine  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402

tmpdir = tempfile.mkdtemp()
os.environ["FAKE_RESTORE_LOG"] = os.path.join(tmpdir, "fake_restore.log")
quiet, real_stdout = open(os.devnull, "w"), sys.stdout
DEV = "192.168.0.1"


def engine(name, containment=None):
    return HealingEngine(ThreatDatabase(os.path.join(tmpdir, name + ".db")), containment=containment)


def win(t, risk):
    label = "benign" if risk < 15 else "suspicious" if risk < 35 else "malicious"
    return {"alert_version": "1.0.0", "type": "window", "emitted_at_epoch": t + 5.1,
            "alert_id": "%s-%.3f" % (DEV, t), "window_start_epoch": t, "window_end_epoch": t + 5,
            "device_ip": DEV, "firmware_id": "DIR-868L_revB_2-05b02", "threat_label": label,
            "threat_probability": risk / 100, "risk_score": risk,
            "explanation": [{"feature": "n_unique_dst_ports", "value": 0.9, "impact": 2.1, "direction": "raises risk", "monitor": "network"},
                            {"feature": "frac_syn", "value": 0.8, "impact": 0.7, "direction": "raises risk", "monitor": "network"},
                            {"feature": "mean_ttl", "value": 0.2, "impact": -0.3, "direction": "lowers risk", "monitor": "network"}],
            "detector_action": "alert_only"}


def run(eng, *pairs):
    sys.stdout = quiet
    try:
        return [eng.handle(win(t, r)) for t, r in pairs]
    finally:
        sys.stdout = real_stdout


# 1. escalations are logged and keep their history after a clear
eng = engine("e1")
run(eng, (0, 99), (100, 99), (200, 99))
assert eng.db.rows("SELECT kind, reason, cleared_by FROM escalations") == [("hold", "3 heals within 10 min", None)]
assert eng.db.clear(DEV, by="Tavishi")
assert eng.db.rows("SELECT kind, cleared_by FROM escalations") == [("hold", "Tavishi")]
print("ok  escalation logged; still there after a clear, with who cleared it")

# 2. after a clear the heal count starts fresh: the next heal within 10 min does NOT re-escalate
r = run(eng, (300, 99))
assert r == ["restored"], r
print("ok  heal right after a clear is not escalated again")

# 3. policy feedback: after an escalation, risk 55 is quarantined (strict) instead of rate-limited
r = run(eng, (500, 55))
assert r == ["restored"], r
assert "strict" in eng.db.rows("SELECT reason FROM actions WHERE alert_id = ?", ("%s-%.3f" % (DEV, 500),))[0][0]
print("ok  escalated device -> stricter policy (risk 55 quarantined)")
fresh = engine("e3")
assert run(fresh, (0, 55)) == ["rate_limit"]
print("ok  same risk 55 on a device never escalated -> only rate-limited")

# 4. stuck in the rate-limit band for 2 min -> notify a human once; back to normal -> rate-limit lifted
eng = engine("e4")
r = run(eng, *[(t, 50) for t in range(0, 130, 5)], (130, 5))
notes = eng.db.rows("SELECT kind, reason FROM escalations")
assert len(notes) == 1 and notes[0][0] == "notify" and "rate-limited" in notes[0][1], notes
steps = [x[0] for x in eng.db.rows("SELECT action FROM containment ORDER BY id")]
assert steps == ["rate_limit", "unlimit"], steps
print("ok  rate-limited 2 min -> human notified once; back to normal -> rate-limit lifted")

# 5. real containment through (fake) Ryu: isolate -> verified -> release
srv = fake_ryu.start(8097)
eng = engine("e5", Containment("ryu", "http://127.0.0.1:8097"))
r = run(eng, (0, 99))
rows = eng.db.rows("SELECT action, mode, ok, verified FROM containment ORDER BY id")
assert rows == [("isolate", "ryu", 1, 1), ("release", "ryu", 1, 1)], rows
assert not fake_ryu.FLOWS, fake_ryu.FLOWS
print("ok  Ryu: drop rules added, verified on the switch, removed after the heal")

# 6. held device stays isolated (rules stay); a human clear lifts them on the next alert
run(eng, (100, 99), (200, 99))
assert eng.db.held_reason(DEV) and len(fake_ryu.FLOWS) == 5, len(fake_ryu.FLOWS)
eng.db.clear(DEV)
run(eng, (300, 2))
assert not fake_ryu.FLOWS, fake_ryu.FLOWS
print("ok  held device keeps its drop rules; after a clear they are removed")

# 7. switch without meters: rate-limit fails -> human notified
os.environ["FAKE_RYU_NO_METER"] = "1"
eng = engine("e7", Containment("ryu", "http://127.0.0.1:8097"))
run(eng, (0, 50))
del os.environ["FAKE_RYU_NO_METER"]
assert eng.db.rows("SELECT ok FROM containment") == [(0,)]
assert "not confirmed" in eng.db.rows("SELECT reason FROM escalations")[0][0]
print("ok  rate-limit not supported by the switch -> recorded as failed, human notified")
srv.shutdown()
fake_ryu.FLOWS.clear()

# 8. Ryu not running: isolate fails, human notified, the heal still runs
eng = engine("e8", Containment("ryu", "http://127.0.0.1:8096"))
r = run(eng, (0, 99))
assert r == ["restored"] and eng.db.rows("SELECT ok FROM containment LIMIT 1") == [(0,)]
print("ok  Ryu unreachable -> containment failure recorded, heal still done")

# 9. health records, indicators, firmware id, trigger risk
eng = engine("e9")
sys.stdout = quiet
eng.handle({"type": "health", "device_ip": DEV, "emitted_at_epoch": 1.0, "alive": True})
sys.stdout = real_stdout
run(eng, (0, 99))
assert eng.db.count("health") == 1
assert eng.db.rows("SELECT feature FROM indicators ORDER BY impact DESC") == [("n_unique_dst_ports",), ("frac_syn",)]
assert eng.db.rows("SELECT firmware_id FROM alerts") == [("DIR-868L_revB_2-05b02",)]
assert eng.db.rows("SELECT trigger_risk FROM heals") == [(99,)]
print("ok  health stored; indicators = only risk-raising features; firmware id and trigger risk stored")

# 10. a threat.db from an earlier step is upgraded
old = os.path.join(tmpdir, "old.db")
c = sqlite3.connect(old)
c.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, device_ip TEXT, window_start_epoch REAL, window_end_epoch REAL, "
          "emitted_at_epoch REAL, threat_label TEXT, threat_probability REAL, risk_score INTEGER, p_xgboost REAL, "
          "p_incremental REAL, top_feature TEXT, explanation_json TEXT, fingerprint_schema TEXT, detector_action TEXT, "
          "synthetic INTEGER DEFAULT 0)")
c.commit(); c.close()
run(HealingEngine(ThreatDatabase(old)), (0, 99))
print("ok  old threat.db upgraded (firmware_id, trigger_risk, new tables)")

print("\nSTEP 8 TESTS PASSED")
