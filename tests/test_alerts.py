#!/usr/bin/env python3
"""tests/test_alerts.py — the alert feed (Person C -> Person D contract).

    python3 tests/test_alerts.py        (from the person3 folder, after training)
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
tmp = tempfile.mkdtemp()
fails = 0
try:
    import jsonschema
    SCHEMA = json.load(open("contracts/alert.schema.json"))
except ImportError:
    jsonschema = None


def check(name, cond, detail=""):
    global fails
    fails += not cond
    print("%s  %s %s" % ("PASS" if cond else "FAIL", name, detail))


def run(extra, env=None):
    out = os.path.join(tmp, "alerts_%d.jsonl" % len(os.listdir(tmp)))
    p = subprocess.run([sys.executable, "live_detector.py", "--quiet", "--input", "data/dataset.jsonl",
                        "--events", os.path.join(tmp, "ev.jsonl"), "--alerts-out", out] + extra,
                       capture_output=True, text=True, env=dict(os.environ, **(env or {})))
    return [json.loads(l) for l in open(out)], p


def valid(recs):
    if jsonschema is None:
        return True
    for r in recs:
        jsonschema.validate(r, SCHEMA)
    return True


FAKE = '"%s" "%s"' % (sys.executable, os.path.join("tests", "fake_restore.py"))

# 1. alerts-only: every one of the 108 windows gets a record, nothing is restored or skipped
recs, p = run(["--alerts-only", "--restore-cmd", FAKE], {"FAKE_RESTORE_LOG": os.path.join(tmp, "r1.log")})
w = [r for r in recs if r["type"] == "window"]
check("alerts-only emits every window and never restores",
      len(w) == 108 and not os.path.exists(os.path.join(tmp, "r1.log")) and not [r for r in recs if r["type"] == "heal"],
      "(windows=%d)" % len(w))
check("alerts-only marks malicious windows alert_only",
      sum(r["detector_action"] == "alert_only" for r in w) == sum(r["threat_label"] == "malicious" for r in w) == 10)
check("records validate against contracts/alert.schema.json", valid(recs),
      "" if jsonschema else "(jsonschema not installed - skipped)")
check("risk score and explanation present",
      all(0 <= r["risk_score"] <= 100 and r["explanation"] and "monitor" in r["explanation"][0] for r in w))

# 2. normal mode: the alert is written BEFORE the restore, and a heal record follows it
recs, p = run(["--restore-cmd", FAKE], {"FAKE_RESTORE_LOG": os.path.join(tmp, "r2.log"), "FAKE_RESTORE_SECONDS": "2"})
heals = [i for i, r in enumerate(recs) if r["type"] == "heal"]
check("normal mode: one heal record per restore", len(heals) == 5 and valid(recs), "(heals=%d)" % len(heals))
ok = all(recs[i - 1]["type"] == "window" and recs[i - 1]["detector_action"] == "restore_started"
         and recs[i]["emitted_at_epoch"] - recs[i - 1]["emitted_at_epoch"] >= 1.5 for i in heals)
check("normal mode: alert emitted before the restore starts, heal record after it ends", ok)

# 3. the shipped samples and the replay tool
names = sorted(f for f in os.listdir("samples") if f.endswith(".jsonl"))
n = 0
for f in names:
    rs = [json.loads(l) for l in open(os.path.join("samples", f))]
    valid(rs); n += len(rs)
check("all sample files validate", n > 0, "(%d files, %d records)" % (len(names), n))
p = subprocess.run([sys.executable, "tools/replay_alerts.py", "samples/alerts_three_monitor_clean_run.jsonl",
                    "--speed", "0", "--now"], capture_output=True, text=True)
rs = [json.loads(l) for l in p.stdout.splitlines()]
check("replay tool plays a sample back", len(rs) == 32 and valid(rs), "(records=%d)" % len(rs))
p2 = subprocess.run([sys.executable, "examples/policy_stub.py"], input=p.stdout, capture_output=True, text=True)
check("example policy stub reads the feed", "QUARANTINE" in p2.stdout and "[heal]" in p2.stdout)

print("\n%s" % ("ALL ALERT TESTS PASSED" if not fails else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
