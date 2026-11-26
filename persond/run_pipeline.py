#!/usr/bin/env python3
"""Step 5 - run_pipeline.py: the whole chain in one command.

  alert feed -> alert_reader (step 1) -> policy (step 2) -> healing_engine (step 4) -> threat.db (step 3)

Three ways to feed it:

  # a. recordings, straight from files
  python persond/run_pipeline.py samples/SYNTHETIC_risk_ladder.jsonl

  # b. a recording replayed at (sped-up) real pace, the way the live feed arrives
  python tools/replay_alerts.py samples/SYNTHETIC_risk_ladder.jsonl --speed 5 | python persond/run_pipeline.py -

  # c. follow a growing file, like `tail -F` (works on Windows too). This is how it will run
  #    on the twin host against: ./run_live.sh --alerts-only   (writes logs/alerts.jsonl)
  python persond/run_pipeline.py --follow logs/alerts.jsonl
  #    to try it on the laptop, in a second terminal:
  #    python tools/replay_alerts.py samples/SYNTHETIC_risk_ladder.jsonl --speed 2 --out logs/alerts.jsonl

Options
  --db PATH            database file (default threat.db)
  --restore-cmd "..."  restore command (default: tests/fake_restore.py). On the twin host this
                       becomes "sudo bash network/twin_net.sh heal" - NOT on the laptop.
  --containment ryu    really isolate / rate-limit through Ryu's REST API (default: print only)
  --ryu-url URL        default http://127.0.0.1:8080
  --dpid N             switch datapath id (default: the first switch Ryu knows)
  --idle-exit N        in --follow mode, stop after N seconds with no new lines (default: never)
Stop with Ctrl-C at any time; a summary is printed.
"""
import argparse
import os
import shlex
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402
from containment import Containment  # noqa: E402
from healing_engine import HealingEngine  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402


def follow(path, idle_exit=None, start_at_end=True):
    """Yield complete new lines appended to path. Waits for the file if it does not exist yet."""
    while not os.path.exists(path):
        time.sleep(0.5)
    f = open(path)
    if start_at_end:
        f.seek(0, os.SEEK_END)           # like tail -n 0: only alerts written from now on
    buf, last = "", time.time()
    while True:
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):        # only hand over whole lines
                yield buf
                buf = ""
            last = time.time()
            continue
        if idle_exit is not None and time.time() - last > idle_exit:
            return
        time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="alert files, or - for stdin")
    ap.add_argument("--follow", metavar="PATH")
    ap.add_argument("--from-start", action="store_true", help="with --follow: also process lines already in the file")
    ap.add_argument("--db", default="threat.db")
    ap.add_argument("--restore-cmd")
    ap.add_argument("--idle-exit", type=float)
    ap.add_argument("--containment", default="print", choices=["print", "ryu"])
    ap.add_argument("--ryu-url", default="http://127.0.0.1:8080")
    ap.add_argument("--dpid", type=int)
    ap.add_argument("--verify", default="windows", choices=["windows", "full"],
                    help="windows = low-risk windows after a heal (default, as before); full = also run "
                         "verify_heal.py's independent checks (baseline hash, boot, service, network, client)")
    ap.add_argument("--accept-http", help="with --verify full: accepted HTTP codes, e.g. 200,302 (default any)")
    ap.add_argument("--client-cmd", help="with --verify full: command that must succeed after a heal")
    ap.add_argument("--background-restore", action="store_true",
                    help="run restores in a worker thread and keep reading alerts meanwhile (IMP-10)")
    ap.add_argument("--service-timeout", type=float,
                    help="with --verify full: seconds to wait for the web UI (default: verify_heal.py's own, 90)")
    a = ap.parse_args()

    if a.follow:
        sources = [("follow " + a.follow, follow(a.follow, a.idle_exit, not a.from_start))]
    elif not a.files or a.files == ["-"]:
        sources = [("stdin", sys.stdin)]
    else:
        sources = [(p, open(p)) for p in a.files]

    db = ThreatDatabase(a.db)
    cont = Containment(a.containment, a.ryu_url, a.dpid)
    verifier = None
    if a.verify == "full":
        from verify_heal import HealVerifier
        extra = {"service_timeout": a.service_timeout} if a.service_timeout else {}
        verifier = HealVerifier(cont, accept_http=[int(x) for x in a.accept_http.split(",")] if a.accept_http else None,
                                client_cmd=a.client_cmd, **extra)
    eng = HealingEngine(db, shlex.split(a.restore_cmd, posix=(os.name != "nt")) if a.restore_cmd else None,
                        containment=cont, verifier=verifier, background=a.background_restore)
    counts = Counter()
    try:
        for name, lines in sources:
            print("=== reading %s" % name, flush=True)
            for alert in read_alerts(lines, on_bad=lambda n, why: print("SKIPPED line %d: %s" % (n, why), file=sys.stderr)):
                counts[eng.handle(alert)] += 1
                sys.stdout.flush()
        for outcome in eng.collect(wait=True):            # end of input: finish background restores
            counts[outcome] += 1
    except KeyboardInterrupt:
        print("\nstopped by Ctrl-C")
    finally:
        # Stopping the engine never lifts a quarantine (IMP-11: releasing here let the attacker back in
        # mid-incident). A restarted engine picks up held devices and interrupted restores from the db.
        left = sorted(eng.isolated | eng.pending_isolate)
        if left:
            print("[stop] containment left in place for %s; release with: python persond/healing_engine.py "
                  "--clear <ip> (then the next engine run lifts it), or python persond/containment.py "
                  "--mode ryu release <ip>" % ", ".join(left))

    print("\n=== summary")
    print("this run:", dict(counts))
    print("database %s: alerts %d | actions %d | heals %d" % (a.db, db.count("alerts"), db.count("actions"), db.count("heals")))
    if eng.escalated:
        print("escalations:", eng.escalated)


if __name__ == "__main__":
    main()
