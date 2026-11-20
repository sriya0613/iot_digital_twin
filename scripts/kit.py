#!/usr/bin/env python3 -I
"""kit.py — testable helpers for the collection kit (collect_session.sh / run_protocol.sh).

  python3 -I scripts/kit.py recorder-iface < <(pgrep -af 'run.py record')
        prints the --iface of the running recorder ('' if none, 'MULTIPLE' if they disagree)
  python3 -I scripts/kit.py session-start --id S01 --tag "operator=sriya" --order scan,dos,...
        writes data/sessions/S01.json (refuses to overwrite an existing session)
  python3 -I scripts/kit.py session-stop --id S01 --status complete
        adds stop time, stop-time host load and status to data/sessions/S01.json
  python3 -I scripts/kit.py beacon-period --id S07
        the long-beacon period for this session (rotates 10 / 30 / 60 s by session number)
  python3 -I scripts/kit.py watchdog-healing < <(pgrep -af watchdog.py)
        'yes' if a self-healing watchdog is running (it would restore the twin mid-session), else 'no'
  python3 -I scripts/kit.py raw-files --iface twin-mon data/raw/session_*.jsonl
        absolute paths of the raw files that are non-empty and were captured on --iface;
        skipped files are named on stderr; exit 2 if none is usable

Session IDs: S01..S99 = real sessions (registered in data/session_split.json);
             P01..P99 = pilot sessions (kit checks only, never in any split; S00 was the first pilot).

Session files are the source of truth for which windows belong to which session
(scripts/merge_sessions.py maps windows to sessions by time).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.environ.get("KIT_SESSIONS_DIR") or os.path.join(ROOT, "data", "sessions")   # env: tests only
PROTOCOL_VERSION = "2.0"           # 1.0 = Oct 16 commands; 2.0 = + login/idle benign, long beacons, session files
SESSION_RE = re.compile(r"^[SP]\d{2}$")      # S = real session, P = pilot (never used in results)
BEACON_PERIODS = (10, 30, 60)


# ------------------------------------------------------------------ recorder interface
def recorder_iface(proc_lines):
    """--iface of running `run.py record`/`run.py stream` processes from `pgrep -af` output."""
    found = set()
    for line in proc_lines:
        if "run.py" not in line or not re.search(r"\brun\.py\s+(record|stream)\b", line):
            continue
        m = re.search(r"--iface[ =](\S+)", line)
        found.add(m.group(1) if m else "tap1_0.1")   # stream/run.py default when --iface is absent
    if not found:
        return ""
    return found.pop() if len(found) == 1 else "MULTIPLE"


# ------------------------------------------------------------------ session metadata
def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else ""
    except Exception:
        return ""


def _sha256(path, n=16):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:n]
    except OSError:
        return None


def host_state():
    s = {}
    try:
        s["loadavg"] = [float(x) for x in open("/proc/loadavg").read().split()[:3]]
        s["uptime_s"] = round(float(open("/proc/uptime").read().split()[0]))
    except OSError:
        pass
    s["cpus"] = os.cpu_count()
    # metadata must never stop a session: anything unexpected is recorded as None
    tok = (_run(["pgrep", "-f", "qemu-system-"]).split() or [""])[0]
    if tok.isdigit():
        s["qemu_pid"] = int(tok)
        et = _run(["ps", "-o", "etimes=", "-p", tok]).strip()
        s["qemu_uptime_s"] = int(et) if et.isdigit() else None
    else:
        s["qemu_pid"] = None
    return s


def tool_versions():
    v = {}
    for name, cmd in (("nmap", ["nmap", "--version"]), ("hping3", ["hping3", "--version"]),
                      ("ovs", ["ovs-vsctl", "--version"]), ("curl", ["curl", "--version"])):
        if shutil.which(cmd[0]):
            v[name] = _run(cmd)
    v["python"] = sys.version.split()[0]
    return v


def git_commit():
    c = _run(["git", "-C", ROOT, "rev-parse", "HEAD"])
    dirty = _run(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"])
    return {"commit": c or None, "tracked_changes": bool(dirty)}


def session_path(sid, sessions_dir=None):
    return os.path.join(sessions_dir or SESSIONS_DIR, sid + ".json")


def session_start(sid, tag="", operator="", order=(), capture_iface="twin-mon", sessions_dir=None, now=None,
                  collect_env=True):
    if not SESSION_RE.match(sid):
        raise ValueError("session id must look like S01..S99 (or P01..P99 for a pilot), got %r" % sid)
    p = session_path(sid, sessions_dir)
    if os.path.exists(p):
        raise FileExistsError("%s exists - session ids are never reused; pick the next free id" % p)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    rec = {"session_id": sid, "protocol_version": PROTOCOL_VERSION, "tag": tag, "operator": operator,
           "episode_order": list(order), "capture_iface": capture_iface,
           "start_epoch": round(now if now is not None else time.time(), 3), "stop_epoch": None, "status": "running",
           "model_sha256_16": _sha256(os.path.join(ROOT, "models_v3_hybrid", "xgboost.json")),
           "beacon_long_period_s": beacon_period(sid)}
    if collect_env:
        rec.update({"host_at_start": host_state(), "tools": tool_versions(), "git": git_commit()})
    with open(p, "x") as f:                      # 'x': fail rather than overwrite if a race created it
        json.dump(rec, f, indent=2)
    return rec


def session_stop(sid, status="complete", sessions_dir=None, now=None, collect_env=True):
    if status not in ("complete", "aborted", "failed"):
        raise ValueError("status must be complete | aborted | failed")
    p = session_path(sid, sessions_dir)
    with open(p) as f:
        rec = json.load(f)
    if rec.get("stop_epoch") is not None:
        raise RuntimeError("%s already stopped" % sid)
    rec["stop_epoch"] = round(now if now is not None else time.time(), 3)
    rec["status"] = status
    if collect_env:
        rec["host_at_stop"] = host_state()
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, p)
    return rec


def watchdog_healing(proc_lines):
    """True if a network/watchdog.py that may heal is running (no --no-heal, not a one-off --status)."""
    for line in proc_lines:
        if "watchdog.py" not in line or re.search(r"\b(grep|pgrep)\b", line):
            continue
        if "--no-heal" in line or "--status" in line:
            continue
        return True
    return False


def raw_files(paths, iface="twin-mon"):
    """(usable absolute paths, [(path, reason)] skipped). A raw file is usable if it is non-empty
    and its first window says it was captured on `iface` (record.sh writes monitors.network)."""
    ok, skipped = [], []
    for p in paths:
        ap = os.path.abspath(p)
        if not os.path.isfile(ap):
            skipped.append((p, "not a file")); continue
        if os.path.getsize(ap) == 0:
            skipped.append((p, "empty")); continue
        try:
            with open(ap) as f:
                first = json.loads(f.readline())
        except (ValueError, OSError) as e:
            skipped.append((p, "unreadable first line: %s" % e)); continue
        got = (first.get("monitors") or {}).get("network")
        if got != iface:
            skipped.append((p, "captured on %r, not %r" % (got, iface))); continue
        ok.append(ap)
    return ok, skipped


def beacon_period(sid):
    """Long-beacon period for a session: rotates through 10/30/60 s so 15 sessions give 5 of each."""
    n = int(sid[1:])
    return BEACON_PERIODS[(n - 1) % len(BEACON_PERIODS)]


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("recorder-iface")
    s = sub.add_parser("session-start")
    s.add_argument("--id", required=True); s.add_argument("--tag", default=""); s.add_argument("--operator", default="")
    s.add_argument("--order", default=""); s.add_argument("--capture-iface", default="twin-mon")
    t = sub.add_parser("session-stop")
    t.add_argument("--id", required=True); t.add_argument("--status", default="complete")
    b = sub.add_parser("beacon-period"); b.add_argument("--id", required=True)
    sub.add_parser("watchdog-healing")
    r = sub.add_parser("raw-files"); r.add_argument("paths", nargs="*"); r.add_argument("--iface", default="twin-mon")
    a = ap.parse_args()
    try:
        if a.cmd == "recorder-iface":
            print(recorder_iface(sys.stdin.read().splitlines()))
        elif a.cmd == "session-start":
            r = session_start(a.id, a.tag, a.operator, [x for x in a.order.split(",") if x], a.capture_iface)
            print(session_path(a.id))
        elif a.cmd == "session-stop":
            session_stop(a.id, a.status); print(session_path(a.id))
        elif a.cmd == "beacon-period":
            if not SESSION_RE.match(a.id):
                raise ValueError("session id must look like S01..S99 or P01..P99")
            print(beacon_period(a.id))
        elif a.cmd == "watchdog-healing":
            print("yes" if watchdog_healing(sys.stdin.read().splitlines()) else "no")
        elif a.cmd == "raw-files":
            ok, skipped = raw_files(a.paths, a.iface)
            for p, why in skipped:
                print("kit.py: skipping %s (%s)" % (p, why), file=sys.stderr)
            if not ok:
                print("kit.py: no usable raw file captured on %s" % a.iface, file=sys.stderr); sys.exit(2)
            print("\n".join(ok))
    except (ValueError, FileExistsError, RuntimeError, FileNotFoundError) as e:
        print("kit.py: %s" % e, file=sys.stderr); sys.exit(2)


if __name__ == "__main__":
    main()
