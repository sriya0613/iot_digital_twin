#!/usr/bin/env python3
"""Step 2 - policy.py: decide what to do about each alert.

Rule (from HANDOFF_to_personD.md / examples/policy_stub.py):
    risk < 30          -> observe     (just watch)
    30 <= risk <= 70   -> rate_limit  (slow the device down)
    risk > 70          -> quarantine  (cut it off, then restore it)

This step only DECIDES and prints. Nothing is blocked, restored or saved yet.

  python persond/policy.py samples/SYNTHETIC_risk_ladder.jsonl
  python tools/replay_alerts.py samples/alerts_three_monitor_clean_run.jsonl --speed 0 | python persond/policy.py
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402

# Band edges. 30 and 70 count as rate_limit, same as examples/policy_stub.py.
# The work-split document is not in the zip - confirm these with the team.
OBSERVE_BELOW = 30
QUARANTINE_ABOVE = 70

# Feedback from Escalate Policy / Threat Database (architecture diagram): a device that was
# escalated in the last hour is treated more strictly - it is quarantined above 50 instead of 70.
STRICT_QUARANTINE_ABOVE = 50

OBSERVE, RATE_LIMIT, QUARANTINE = "observe", "rate_limit", "quarantine"


def decide(alert, strict=False):
    """Return (action, reason) for one window alert. Other records return (None, reason).
    strict=True (device escalated recently) lowers the quarantine edge to STRICT_QUARANTINE_ABOVE."""
    if alert["type"] != "window":
        return None, "%s record - nothing to decide" % alert["type"]
    risk = alert["risk_score"]
    top = alert["explanation"][0]["feature"] if alert["explanation"] else "no explanation"
    q = STRICT_QUARANTINE_ABOVE if strict else QUARANTINE_ABOVE
    tag = " (strict: escalated recently)" if strict else ""
    if risk < OBSERVE_BELOW:
        return OBSERVE, "risk %d < %d" % (risk, OBSERVE_BELOW)
    if risk <= q:
        return RATE_LIMIT, "risk %d in %d-%d, top feature %s%s" % (risk, OBSERVE_BELOW, q, top, tag)
    return QUARANTINE, "risk %d > %d, top feature %s%s" % (risk, q, top, tag)


def main():
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    counts = Counter()
    for a in read_alerts(src, on_bad=lambda n, why: print("SKIPPED line %d: %s" % (n, why), file=sys.stderr)):
        action, reason = decide(a)
        if a["type"] == "health":
            continue
        if action is None:
            print("[heal]  device %s restored: ok=%s in %.0f s" % (a.get("device_ip"), a["ok"], a["restore_seconds"]))
            continue
        counts[action] += 1
        print("[risk %3d] %-10s -> %-10s %s" % (a["risk_score"], a["threat_label"], action.upper(), reason))
    print("\nsummary:", dict(counts))


if __name__ == "__main__":
    main()
