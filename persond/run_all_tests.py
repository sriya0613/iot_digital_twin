#!/usr/bin/env python3
"""Run every Person D test and the evaluation report once. Run from the personD_handoff folder:
    python persond/run_all_tests.py
Takes about a minute. Ends with ALL PERSON D TESTS PASSED, or names the test that failed."""
import glob
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
failed = []
for test in sorted(glob.glob(os.path.join(HERE, "test_step*.py"))):
    name = os.path.basename(test)
    p = subprocess.run([sys.executable, test], capture_output=True, text=True)
    last = [l for l in p.stdout.strip().splitlines() if l.strip()][-1:] or ["(no output)"]
    ok = p.returncode == 0 and "PASSED" in last[0]
    print("%-42s %s" % (name, "ok" if ok else "FAILED"))
    if not ok:
        failed.append(name)
        print(p.stdout[-1500:], p.stderr[-1500:])

# the evaluation report must run on a database filled from the samples
db = os.path.join(tempfile.mkdtemp(), "eval.db")
env = dict(os.environ, FAKE_RESTORE_LOG=os.path.join(os.path.dirname(db), "r.log"))
subprocess.run([sys.executable, os.path.join(HERE, "run_pipeline.py"), "--db", db] + sorted(glob.glob("samples/*.jsonl")),
               env=env, capture_output=True, check=True)
p = subprocess.run([sys.executable, os.path.join(HERE, "evaluate.py"), "--db", db], capture_output=True, text=True)
ok = p.returncode == 0 and "| heals | 7 |" in p.stdout
print("%-42s %s" % ("evaluate.py on the samples", "ok" if ok else "FAILED"))
if not ok:
    failed.append("evaluate.py")
    print(p.stdout[-1500:], p.stderr[-1500:])

print("\nALL PERSON D TESTS PASSED" if not failed else "\nFAILED: " + ", ".join(failed))
sys.exit(1 if failed else 0)
