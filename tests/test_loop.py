#!/usr/bin/env python3
"""tests/test_loop.py — end-to-end check of the detect -> heal loop without the twin.

    python3 tests/test_loop.py        (run from the person3 folder, after training)

Uses tests/fake_restore.py in place of Person 1's restore.sh.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
FAKE = '"%s" "%s"' % (sys.executable, os.path.join("tests", "fake_restore.py"))   # runs on any OS
RECS = [json.loads(l) for l in open("data/dataset.jsonl")]
tmp = tempfile.mkdtemp()
fails = 0


def run(stdin_text, extra, env=None):
    log = os.path.join(tmp, "restore_%d.log" % time.time_ns())
    e = dict(os.environ, FAKE_RESTORE_LOG=log, **(env or {}))
    p = subprocess.run([sys.executable, "live_detector.py", "--quiet", "--events",
                        os.path.join(tmp, "ev_%d.jsonl" % time.time_ns())] + extra,
                       input=stdin_text, capture_output=True, text=True, env=e)
    calls = len(open(log).readlines()) if os.path.exists(log) else 0
    return p, calls


def check(name, cond, detail=""):
    global fails
    fails += not cond
    print("%s  %s %s" % ("PASS" if cond else "FAIL", name, detail))


text = "".join(json.dumps(r) + "\n" for r in RECS)

# 1. replay: 5 scan episodes in the capture -> exactly 5 restores, none on normal traffic
p, calls = run(text, ["--restore-cmd", FAKE])
check("replay fires one restore per scan episode", calls == 5, "(restores=%d)" % calls)

# 2. benign-only traffic never triggers a restore
benign = "".join(json.dumps(r) + "\n" for r in RECS if r["label"] == "benign")
p, calls = run(benign, ["--restore-cmd", FAKE])
check("benign run triggers no restore", calls == 0, "(restores=%d)" % calls)

# 3. dry-run never calls the restore script
p, calls = run(text, ["--restore-cmd", FAKE, "--dry-run"])
check("dry-run never calls restore", calls == 0 and "dry-run" in p.stdout)

# 4. failing restore is reported, detector keeps running
p, calls = run(text, ["--restore-cmd", FAKE], {"FAKE_RESTORE_EXIT": "1"})
check("failed restore is reported and loop survives", "RESTORE FAILED" in p.stdout and p.returncode == 0)

# 5. garbage / wrong-schema lines are skipped, not fatal
bad = "hello log line\n{not json\n" + json.dumps(dict(RECS[0], schema_version="9.9.9")) + "\n" + text
p, calls = run(bad, ["--restore-cmd", FAKE])
check("bad lines are skipped", calls == 5 and "bad 2" in p.stdout, "(restores=%d)" % calls)

# 6. live timing: windows captured while the restore is running are discarded
now = time.time()
scan = next(r for r in RECS if r["window_id"] == 47)
live = []
for i in range(6):                                # 6 back-to-back scan windows, 5 s apart
    r = dict(scan, window_id=i, window_start_epoch=now + 5 * i, window_end_epoch=now + 5 * i + 5)
    live.append(json.dumps(r) + "\n")
p, calls = run("".join(live), ["--restore-cmd", FAKE, "--grace", "10"], {"FAKE_RESTORE_SECONDS": "12"})
check("cool-down: one restore for a 30 s attack with a 12 s restore", calls == 1, "(restores=%d)" % calls)

# 7. --confirm 2 needs two consecutive alarm windows (single-window scan at id 41 is not enough)
p, calls = run(text, ["--restore-cmd", FAKE, "--confirm", "2"])
check("--confirm 2 skips the single-window scan", calls == 4, "(restores=%d)" % calls)

# 8. online learning on: same heals, incremental model actually updated
p, calls = run(text, ["--restore-cmd", FAKE, "--online-update"])
check("--online-update keeps the same decisions", calls == 5 and "incremental updates" in p.stdout,
      "(restores=%d)" % calls)

# 9. every scored window carries a risk score and SHAP feature impact in the event log
evp = os.path.join(tmp, "ev_check.jsonl")
subprocess.run([sys.executable, "live_detector.py", "--quiet", "--dry-run", "--input", "data/dataset.jsonl",
                "--events", evp], capture_output=True, text=True)
evs = [json.loads(l) for l in open(evp)]
scored = [e for e in evs if "risk_score" in e]
check("event log has probability, label, risk score and feature impact",
      scored and all(0 <= e["risk_score"] <= 100 and isinstance(e["feature_impact"], list)
                     and e["threat_label"] in ("benign", "suspicious", "malicious") for e in scored),
      "(windows=%d)" % len(scored))

print("\n%s" % ("ALL TESTS PASSED" if not fails else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
