#!/usr/bin/env python3
"""Test for step 7 (dashboard). Run from the personD_handoff folder:  python persond/test_step7_dashboard.py
Fills a temporary database from the samples and runs the dashboard headless (no browser)."""
import glob
import os
import subprocess
import sys
import tempfile

from streamlit.testing.v1 import AppTest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from threat_db import ThreatDatabase  # noqa: E402

tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "dash.db")
env = dict(os.environ, FAKE_RESTORE_LOG=os.path.join(tmp, "r.log"))
subprocess.run([sys.executable, "persond/run_pipeline.py", "--db", db] + sorted(glob.glob("samples/*.jsonl")),
               env=env, check=True, capture_output=True)


def run_app(path):
    os.environ["THREAT_DB"] = path
    at = AppTest.from_file(os.path.join(HERE, "dashboard.py"), default_timeout=60)
    at.run()
    assert not at.exception, at.exception
    return at, " ".join(m.value for m in at.markdown)


# 1. empty database -> friendly empty state
at, page = run_app(os.path.join(tmp, "empty.db"))
assert "Waiting for alerts" in page
print("ok  no data -> 'Waiting for alerts' with the command to start")

# 2. full database -> header, cards, timeline, why, heals, actions
at, page = run_app(db)
for text in ("192.168.0.1", "DIR-868L", "Cooling down", "Current risk", "Alerts processed", "Heals done", "Escalations",
             "Risk timeline", "Why — latest alert", "Heal history", "Recent actions", "No device is held"):
    assert text in page, text
assert ">99<" in page and ">7<" in page                     # alerts processed, heals done
print("ok  header, 4 cards, timeline, why panel, heal history and recent actions shown")

# 3. every run can be selected
for i in range(len(at.selectbox[0].options)):
    at.selectbox[0].select_index(i).run()
    assert not at.exception, (i, at.exception)
print("ok  all %d runs render" % len(at.selectbox[0].options))

# 4. held device -> red pill + banner; Clear button releases it
ThreatDatabase(db).hold("192.168.0.1", "3 heals within 10 min", 1791200100)
at, page = run_app(db)
assert "Held for human" in page and "is held for a human" in page
at.button[0].click().run()
assert ThreatDatabase(db).held_reason("192.168.0.1") is None
assert ThreatDatabase(db).rows("SELECT cleared_by FROM escalations") == [("dashboard",)]
print("ok  held device shown; Clear releases it and the escalation log records 'dashboard'")

print("\nSTEP 7 TESTS PASSED")
