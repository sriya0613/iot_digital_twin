#!/usr/bin/env python3
"""
label_run.py — write one line to run_manifest.jsonl around a run, so the windows
recorded during it get the right label.

  # label exactly the seconds an attack tool is running
  python3 label_run.py --label malware -- sudo nmap -T4 -p 1-1000 192.168.0.1

  # label the next 120 seconds as benign (browse the web UI, ping, ...)
  python3 label_run.py --label benign --seconds 120

  # label a restore and the boot that follows it, so the detector learns it is normal
  python3 label_run.py --label healing --pad 150 -- ./twin.sh restart

Run it while `run.py record` is capturing in another terminal.
"""
import argparse
import json
import subprocess
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, choices=["benign", "malware", "healing"])
    ap.add_argument("--manifest", default="run_manifest.jsonl")
    ap.add_argument("--seconds", type=float, help="label this many seconds from now")
    ap.add_argument("--note", default="", help="free text, e.g. the attack type")
    ap.add_argument("--pad", type=float, default=0, help="keep labelling this many seconds after the "
                    "command ends (e.g. the device is still booting after restore.sh returns)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run and label")
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd and not a.seconds:
        sys.exit("give either --seconds N or a command after --")

    start = time.time()
    run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime(start)) + "-" + a.label
    print("[label_run] %s started (%s)" % (a.label, run_id), flush=True)
    code = 0
    try:
        if cmd:
            code = subprocess.call(cmd)
            if a.pad > 0:
                print("[label_run] command finished - labelling %.0f more seconds, please wait" % a.pad, flush=True)
                time.sleep(a.pad)
        else:
            time.sleep(a.seconds)
    except KeyboardInterrupt:
        print("[label_run] interrupted - labelling up to now", flush=True)
    stop = time.time()
    with open(a.manifest, "a") as f:
        f.write(json.dumps({"run_id": run_id, "label": a.label, "start_epoch": round(start, 3),
                            "stop_epoch": round(stop, 3), "note": a.note or " ".join(cmd)}) + "\n")
    print("[label_run] %s: %.1f s written to %s" % (a.label, stop - start, a.manifest), flush=True)
    sys.exit(code)


if __name__ == "__main__":
    main()
