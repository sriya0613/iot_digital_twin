#!/usr/bin/env python3 -I
"""merge_sessions.py — give every window in a built dataset its session_id.

  python3 -I scripts/merge_sessions.py data/dataset_v4.jsonl
        reads data/sessions/*.json, writes data/dataset_v4_sessions.jsonl (input is never modified)

Rules
  * a window belongs to session S if its midpoint lies inside S's [start_epoch, stop_epoch];
  * windows earlier than the first session file are legacy data and get "L<YYYYMMDD>" (UTC date of
    the window), e.g. L20261016 - legacy data stays identifiable and is never mixed with S01..S99;
  * any other window (between sessions, recorder running before/after a session) gets None;
  * a labelled (benign/malware) window outside every session is reported, because it means a run
    was labelled while no session was open;
  * overlapping sessions, or a session without stop_epoch (still running / crashed) are errors,
    unless --allow-open lets an open session end at its last labelled run.
"""
import argparse
import glob
import json
import os
import sys
import time
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_sessions(sessions_dir, allow_open=False):
    sess = []
    for p in sorted(glob.glob(os.path.join(sessions_dir, "S*.json"))):
        with open(p) as f:
            s = json.load(f)
        if s.get("stop_epoch") is None:
            if not allow_open:
                raise ValueError("%s has no stop_epoch (session still running or crashed); "
                                 "finish it with kit.py session-stop or pass --allow-open" % s["session_id"])
            s = dict(s, stop_epoch=float("inf"))
        sess.append(s)
    sess.sort(key=lambda s: s["start_epoch"])
    for a, b in zip(sess, sess[1:]):
        if b["start_epoch"] < a["stop_epoch"]:
            raise ValueError("sessions %s and %s overlap" % (a["session_id"], b["session_id"]))
    return sess


def assign(windows, sessions):
    """Return list of session ids (str or None), one per window."""
    first = sessions[0]["start_epoch"] if sessions else float("inf")
    out = []
    for w in windows:
        mid = (float(w["window_start_epoch"]) + float(w["window_end_epoch"])) / 2
        sid = None
        for s in sessions:
            if s["start_epoch"] <= mid <= s["stop_epoch"]:
                sid = s["session_id"]
                break
        if sid is None and mid < first:
            sid = "L" + time.strftime("%Y%m%d", time.gmtime(mid))
        out.append(sid)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--sessions-dir", default=os.path.join(ROOT, "data", "sessions"))
    ap.add_argument("--out")
    ap.add_argument("--allow-open", action="store_true")
    a = ap.parse_args()
    default_out = (a.dataset[:-len(".jsonl")] + "_sessions.jsonl") if a.dataset.endswith(".jsonl") else a.dataset + ".sessions"
    out = a.out or default_out
    if os.path.abspath(out) == os.path.abspath(a.dataset):
        sys.exit("refusing to overwrite the input dataset")
    sessions = load_sessions(a.sessions_dir, a.allow_open)
    with open(a.dataset) as f:
        windows = [json.loads(l) for l in f if l.strip()]
    sids = assign(windows, sessions)
    orphan = Counter()
    with open(out, "w") as f:
        for w, sid in zip(windows, sids):
            w["session_id"] = sid
            if sid is None and w.get("label") in ("benign", "malware"):
                orphan[w.get("run_id")] += 1
            f.write(json.dumps(w) + "\n")
    c = Counter((sid, w.get("label")) for w, sid in zip(windows, sids))
    print("wrote %s (%d windows, %d session files)" % (out, len(windows), len(sessions)))
    for sid in sorted({s for s, _ in c}, key=lambda s: (s is None, str(s))):
        print("  %-10s %s" % (sid, {l: n for (s, l), n in c.items() if s == sid}))
    if orphan:
        print("WARNING: labelled windows outside every session (run_id: windows): %s" % dict(orphan))
        sys.exit(1)


if __name__ == "__main__":
    main()
