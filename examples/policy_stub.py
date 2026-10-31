#!/usr/bin/env python3
"""policy_stub.py — a minimal consumer of the alert feed, as a starting point for the
policy engine. It only PRINTS what it would do; nothing here touches the network or
the twin. Replace the three functions marked TODO with the real response.

  # against a recording (no twin needed)
  python3 tools/replay_alerts.py samples/SYNTHETIC_risk_ladder.jsonl --speed 0 | python3 examples/policy_stub.py
  python3 tools/replay_alerts.py samples/alerts_three_monitor_clean_run.jsonl --speed 20 | python3 examples/policy_stub.py

  # against the live detector, which then only raises alerts and leaves the response to you
  ./run_live.sh --alerts-only          (terminal 1, writes logs/alerts.jsonl)
  tail -n 0 -F logs/alerts.jsonl | python3 examples/policy_stub.py          (terminal 2)

Risk bands are the ones in the project work-split document:
  risk < 30 observe | 30-70 rate-limit + alert | > 70 quarantine + escalate
"""
import json
import sys

OBSERVE_BELOW, QUARANTINE_ABOVE = 30, 70
ESCALATE_AFTER = 3            # this many quarantines of one device -> escalate


def rate_limit(device_ip, alert):                     # TODO: Ryu / OVS meter or queue for device_ip
    print("    -> would RATE-LIMIT %s" % device_ip)


def quarantine(device_ip, alert):                     # TODO: Ryu drop rule, then verify the rule is installed
    print("    -> would QUARANTINE %s (drop its traffic), then restore it from the clean baseline" % device_ip)


def record(device_ip, alert, action):                 # TODO: write to the threat database
    pass


def main():
    strikes = {}
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        a = json.loads(line)
        if a.get("type") == "heal":
            print("[heal] device %s restored by the detector: ok=%s in %.0f s" % (
                a.get("device_ip"), a["ok"], a["restore_seconds"]))
            continue
        if a.get("type") == "health":                # from network/watchdog.py
            print("[health] %s: %s (state %s)" % (a.get("device_ip"), a["event"], a["state"]))
            continue
        if a.get("type") != "window":
            continue
        risk, dev = a["risk_score"], a.get("device_ip") or "device"
        why = ", ".join("%s %+.2f" % (e["feature"], e["impact"]) for e in a["explanation"][:3])
        if risk < OBSERVE_BELOW:
            action = "observe"
        elif risk <= QUARANTINE_ABOVE:
            action = "rate_limit"
        else:
            action = "quarantine"
        if action != "observe":
            print("[risk %3d] %s %s  %s  (%s)" % (risk, dev, a["threat_label"], action.upper(), why))
        if action == "rate_limit":
            rate_limit(dev, a)
        elif action == "quarantine":
            if a.get("detector_action") == "restore_started":
                print("    (the detector is already restoring this device - run it with --alerts-only to own the response)")
            quarantine(dev, a)
            strikes[dev] = strikes.get(dev, 0) + 1
            if strikes[dev] >= ESCALATE_AFTER:
                print("    -> ESCALATE: %s quarantined %d times" % (dev, strikes[dev]))
        record(dev, a, action)


if __name__ == "__main__":
    main()
