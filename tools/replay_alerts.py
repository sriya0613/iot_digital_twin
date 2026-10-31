#!/usr/bin/env python3
"""replay_alerts.py — play a recorded alert file back as if the detector were live.

Lets the policy engine, response code and dashboard be built and tested without the
twin: point them at the output file (or pipe stdout) exactly as they would be pointed
at the live feed from `live_detector.py --alerts-out`.

  python3 tools/replay_alerts.py samples/alerts_three_monitor_clean_run.jsonl            # real-time pace, to stdout
  python3 tools/replay_alerts.py samples/alerts_three_monitor_clean_run.jsonl --speed 10  # 10x faster
  python3 tools/replay_alerts.py samples/alerts_three_monitor_clean_run.jsonl --speed 0 --out logs/alerts.jsonl
  python3 tools/replay_alerts.py samples/*.jsonl --speed 0 --loop 3 --out logs/alerts.jsonl

--speed 0 writes everything at once. --now rewrites the timestamps so the replay looks
like it is happening now (alert_id is rebuilt to match).
"""
import argparse
import json
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--speed", type=float, default=1.0, help="1 = recorded pace, 10 = ten times faster, 0 = no waiting")
    ap.add_argument("--out", default="-", help="file to append to (default: stdout)")
    ap.add_argument("--loop", type=int, default=1, help="play the files this many times")
    ap.add_argument("--now", action="store_true", help="shift all timestamps so the replay starts now")
    a = ap.parse_args()

    recs = []
    for path in a.files:
        with open(path) as f:
            recs += [json.loads(l) for l in f if l.strip().startswith("{")]
    if not recs:
        sys.exit("no alert records in %s" % ", ".join(a.files))
    out = sys.stdout if a.out == "-" else open(a.out, "a")

    for _ in range(a.loop):
        shift = (time.time() - recs[0]["emitted_at_epoch"]) if a.now else 0.0
        prev = None
        for r in recs:
            if a.speed > 0 and prev is not None:
                gap = r["emitted_at_epoch"] - prev
                if 0 < gap < 600:                      # skip the long gaps between recorded sessions
                    time.sleep(gap / a.speed)
                elif gap >= 600:
                    time.sleep(1.0 / a.speed)
            prev = r["emitted_at_epoch"]
            if shift:
                r = dict(r)
                for k in ("emitted_at_epoch", "window_start_epoch", "window_end_epoch", "ignoring_windows_until_epoch"):
                    if k in r:
                        r[k] = round(r[k] + shift, 3)
                if r.get("type") == "window":
                    r["alert_id"] = "%s-%.3f" % (r.get("device_ip") or "device", r["window_start_epoch"])
            out.write(json.dumps(r) + "\n"); out.flush()


if __name__ == "__main__":
    main()
