#!/usr/bin/env python3
"""Step 1 - alert_reader.py: read the detector's alert feed and check every line.

Reads JSON Lines (a file or stdin), checks each record against
contracts/alert.schema.json, and hands back only the good ones.
Bad lines are reported and skipped - they never crash the program.

  python persond/alert_reader.py samples/alerts_three_monitor_clean_run.jsonl
  python tools/replay_alerts.py samples/SYNTHETIC_risk_ladder.jsonl --speed 0 | python persond/alert_reader.py
"""
import json
import os
import sys
from collections import Counter

from jsonschema import Draft7Validator

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "..", "contracts", "alert.schema.json")

with open(SCHEMA_PATH) as f:
    _validator = Draft7Validator(json.load(f))


def check(record):
    """Return a list of problems with one record (empty list = record is fine)."""
    return [e.message for e in _validator.iter_errors(record)]


def read_alerts(lines, on_bad=None):
    """Yield valid alert records from an iterable of text lines.
    on_bad(line_number, reason) is called for every line that is skipped."""
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            if on_bad:
                on_bad(n, "not JSON: %s" % e)
            continue
        if not isinstance(rec, dict):
            if on_bad:
                on_bad(n, "not a JSON object")
            continue
        if rec.get("type") == "health":
            # Person A's watchdog writes 'health' records into the same feed. They are not in
            # alert.schema.json v1.0.0 and their format is not fixed yet, so they are passed on
            # unchecked (stored as raw JSON in the health table).
            yield rec
            continue
        problems = check(rec)
        if problems:
            if on_bad:
                on_bad(n, "; ".join(problems))
            continue
        yield rec


def main():
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    bad = []
    counts = Counter()
    for rec in read_alerts(src, on_bad=lambda n, why: bad.append((n, why))):
        if rec["type"] == "window":
            counts["window/" + rec["threat_label"]] += 1
            print("window %-28s risk %3d  %-10s detector_action=%s" % (
                rec["alert_id"], rec["risk_score"], rec["threat_label"], rec["detector_action"]))
        else:
            counts["heal"] += 1
            print("heal   device %-21s ok=%s  %.1f s" % (
                rec.get("device_ip", "?"), rec["ok"], rec["restore_seconds"]))
    for n, why in bad:
        print("SKIPPED line %d: %s" % (n, why), file=sys.stderr)
    print("\nsummary: %s, skipped %d" % (dict(sorted(counts.items())), len(bad)))


if __name__ == "__main__":
    main()
