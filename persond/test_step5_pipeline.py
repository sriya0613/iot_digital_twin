#!/usr/bin/env python3
"""Test for step 5. Run from the personD_handoff folder:  python persond/test_step5_pipeline.py
Runs the real commands (as separate programs) against temporary files. Takes about 15 seconds."""
import glob
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

PY = sys.executable
tmp = tempfile.mkdtemp()
env = dict(os.environ, FAKE_RESTORE_LOG=os.path.join(tmp, "fake_restore.log"))


def restores():
    p = env["FAKE_RESTORE_LOG"]
    return len(open(p).readlines()) if os.path.exists(p) else 0


def q(db, sql):
    return sqlite3.connect(db).execute(sql).fetchall()


# 1. all recordings, from files
db1 = os.path.join(tmp, "a.db")
files = sorted(glob.glob("samples/*.jsonl"))
out = subprocess.run([PY, "persond/run_pipeline.py", "--db", db1] + files, env=env,
                     capture_output=True, text=True, timeout=120)
assert out.returncode == 0, out.stderr
windows = sum(sum('"type": "window"' in l for l in open(f)) for f in files)
assert q(db1, "SELECT COUNT(*) FROM alerts")[0][0] == windows
assert q(db1, "SELECT COUNT(*) FROM actions")[0][0] == windows
# we restore 3 times: the synthetic attack + the 2 dry runs (there the detector only said would_restore).
# The 4 real heal runs were restored by the detector itself, so we must not restore them again.
assert restores() == 3, restores()
# files are not in time order (synthetic is newest); a restore must not mute OLDER alerts
first_dry = q(db1, "SELECT action FROM actions WHERE alert_id = '192.168.0.1-1790965252.075'")
assert first_dry == [("observe",)], first_dry
print("ok  all %d sample files: %d alerts stored, 3 restores by us, none doubled" % (len(files), windows))

# 2. through a pipe from replay_alerts.py, the way the live feed arrives
db2 = os.path.join(tmp, "b.db")
replay = subprocess.Popen([PY, "tools/replay_alerts.py", "samples/SYNTHETIC_risk_ladder.jsonl", "--speed", "50"],
                          stdout=subprocess.PIPE, env=env)
out = subprocess.run([PY, "persond/run_pipeline.py", "--db", db2, "-"], stdin=replay.stdout, env=env,
                     capture_output=True, text=True, timeout=120)
replay.wait()
assert out.returncode == 0, out.stderr
assert "'restored': 1" in out.stdout and "'ignored': 6" in out.stdout, out.stdout
print("ok  piped replay: 1 restored, 6 ignored")

# 3. --follow a file that another program is still writing (the live setup)
db3 = os.path.join(tmp, "c.db")
feed = os.path.join(tmp, "alerts.jsonl")
open(feed, "w").close()
follower = subprocess.Popen([PY, "persond/run_pipeline.py", "--db", db3, "--follow", feed, "--idle-exit", "4"],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1.5)                                   # let it start and wait at the end of the file
subprocess.run([PY, "tools/replay_alerts.py", "samples/SYNTHETIC_risk_ladder.jsonl", "--speed", "20", "--out", feed],
               env=env, check=True, timeout=60)
so, se = follower.communicate(timeout=60)
assert follower.returncode == 0, se
assert q(db3, "SELECT COUNT(*) FROM alerts")[0][0] == 18, so
print("ok  --follow picked up all 18 alerts while they were being written")

print("\nSTEP 5 TESTS PASSED")
