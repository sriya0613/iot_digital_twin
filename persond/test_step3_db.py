#!/usr/bin/env python3
"""Test for step 3. Run from the personD_handoff folder:  python persond/test_step3_db.py
Uses a temporary database file, so your threat.db is not touched."""
import glob
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_db import ThreatDatabase, load  # noqa: E402

tmp = os.path.join(tempfile.mkdtemp(), "test_threat.db")
db = ThreatDatabase(tmp)

# 1. load every sample file
files = sorted(glob.glob("samples/*.jsonl"))
total_windows = total_heals = 0
for path in files:
    lines = open(path).readlines()
    total_windows += sum('"type": "window"' in l for l in lines)
    total_heals += sum('"type": "heal"' in l for l in lines)
    load(db, lines)
assert db.count("alerts") == total_windows, (db.count("alerts"), total_windows)
assert db.count("actions") == total_windows
assert db.count("heals") == total_heals
print("ok  stored %d alerts, %d actions, %d heals" % (total_windows, total_windows, total_heals))

# 2. loading the same files again adds nothing (alert_id is the key)
for path in files:
    new, dup = load(db, open(path))
    assert new == 0, path
assert db.count("alerts") == total_windows and db.count("heals") == total_heals
print("ok  re-loading adds no duplicates")

# 3. every malicious alert with risk > 70 has a quarantine action
bad = db.rows("SELECT a.alert_id FROM alerts a JOIN actions x USING (alert_id) "
              "WHERE a.risk_score > 70 AND x.action != 'quarantine'")
assert not bad, bad
print("ok  every risk > 70 alert is stored as quarantine")

# 4. data survives closing and reopening the file
db.con.close()
assert ThreatDatabase(tmp).count("alerts") == total_windows
print("ok  data is still there after reopening")

print("\nSTEP 3 TESTS PASSED")
