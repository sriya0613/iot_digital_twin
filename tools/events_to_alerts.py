#!/usr/bin/env python3
"""events_to_alerts.py — convert an older logs/events.jsonl (written before --alerts-out
existed) into alert records (contracts/alert.schema.json).

  python3 tools/events_to_alerts.py logs/events.jsonl > alerts.jsonl

The old log wrote a window's row only after its restore had finished, so for restored
windows emitted_at_epoch is set to the window's end + 1 s, which is when the detector
printed the verdict in the recorded runs.
"""
import json
import sys

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))
from common import monitor_of                                                      # noqa: E402

DEVICE_IP, FIRMWARE, IFACE = "192.168.0.1", "DIR-868L_revB_2-05b02", "tap1_0.1"
ACTION = {"none": "none", "restored": "restore_started", "restore_failed": "restore_started",
          "would_restore": "would_restore", "suppressed_max_heals": "suppressed_max_heals", "alert_only": "alert_only"}


def convert(path):
    rows = [json.loads(l) for l in open(path) if l.strip().startswith("{")]
    out, pending_heal = [], None
    for r in rows:
        if r.get("event") == "restore":
            pending_heal = r                       # belongs to the window row that follows it
            continue
        if "threat_probability" not in r:
            continue                               # cool-down rows: the detector did not score these
        feats = r.get("feature_impact", [])
        schema = "2.0.0" if any(monitor_of(f["feature"]) != "network" for f in feats) else None
        act = ACTION.get(r.get("action", "none"), "none")
        emitted = r["logged_at_epoch"] if pending_heal is None else round(r["window_end_epoch"] + 1.0, 3)
        w = {"alert_version": "1.0.0", "emitted_at_epoch": emitted, "type": "window",
             "alert_id": "%s-%.3f" % (DEVICE_IP, r["window_start_epoch"]), "window_id": r.get("window_id"),
             "window_start_epoch": r["window_start_epoch"], "window_end_epoch": r["window_end_epoch"],
             "device_ip": DEVICE_IP, "firmware_id": FIRMWARE, "interface": IFACE,
             "threat_label": r["threat_label"], "threat_probability": r["threat_probability"],
             "risk_score": r["risk_score"], "p_xgboost": r["p_xgboost"], "p_incremental": r["p_incremental"],
             "explanation": [dict(f, monitor=monitor_of(f["feature"])) for f in feats],
             "detector_action": act}
        if schema:
            w["fingerprint_schema"] = schema
        out.append(w)
        if pending_heal is not None:
            h = pending_heal
            out.append({"alert_version": "1.0.0", "emitted_at_epoch": h["logged_at_epoch"], "type": "heal",
                        "window_id": h.get("window_id"), "window_end_epoch": r["window_end_epoch"],
                        "device_ip": DEVICE_IP, "ok": bool(h["ok"]), "exit_code": h["exit_code"],
                        "restore_seconds": h["restore_seconds"]})
            pending_heal = None
    return out


if __name__ == "__main__":
    for path in sys.argv[1:]:
        for rec in convert(path):
            print(json.dumps(rec))
