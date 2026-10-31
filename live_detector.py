#!/usr/bin/env python3
"""live_detector.py — Person 3: score live windows, explain them, close the loop.

Reads Person 2's fingerprint records (one JSON per line) from stdin or a file.
For every 5-second window:

    fingerprint -> XGBoost + incremental model -> fused threat probability
                -> threshold logic -> threat label (benign / suspicious / malicious)
    SHAP on XGBoost -> feature impact -> final risk score (0-100)

When a window is labelled malicious it calls Person 1's restore.sh so the twin
heals itself.

  # live, closed loop (on the FirmAE/Mininet host):
  sudo python3 run.py stream ... | python3 live_detector.py --restore-cmd "sudo ./restore.sh"

  # live, detection only (never touches the device):
  sudo python3 run.py stream ... | python3 live_detector.py --dry-run

  # follow a file that the stream is appending to:
  python3 live_detector.py --follow stream.jsonl --restore-cmd "sudo ./restore.sh"

  # offline replay of a recorded dataset:
  python3 live_detector.py --input data/dataset.jsonl --dry-run

Heal policy
  * trigger    : --confirm N consecutive "malicious" windows (default 1 = react in <= 5 s)
  * restore    : runs --restore-cmd and waits; exit code 0 means healed
  * cool-down  : windows captured before the restore finished (+ --grace seconds)
                 are discarded, so traffic from the attack / the reboot itself
                 cannot trigger a second restore
  * safety cap : stops triggering after --max-heals restores (default 10)

Incremental learning
  With --online-update the incremental model keeps learning during the run from
  windows the fused model is very sure about (probability <= 0.05 or >= 0.95).
  It is OFF by default: see the README before turning it on.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time

from joblib import dump

from common import BadRecord, check_record, to_vector, monitor_of

ALERT_VERSION = "1.0.0"     # contracts/alert.schema.json - the seam between Person C and Person D
from threat_model import ThreatModel
try:
    from threat_model_v3 import HybridModel
except Exception:
    HybridModel = None


def utc(ts=None):
    return time.strftime("%H:%M:%S", time.gmtime(ts if ts is not None else time.time()))


def lines_stdin():
    for line in iter(sys.stdin.readline, ""):
        yield line


def lines_file(path):
    with open(path) as f:
        for line in f:
            yield line


def lines_follow(path, poll=0.5):
    """tail -f : wait for the file, then yield new lines forever."""
    while not os.path.exists(path):
        time.sleep(poll)
    with open(path) as f:
        buf = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(poll)
                continue
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""


def split_cmd(cmd):
    """Split a command line into arguments on both Linux and Windows
    (Windows paths contain backslashes, which POSIX splitting would eat)."""
    if os.name == "nt":
        return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t
                for t in shlex.split(cmd, posix=False)]
    return shlex.split(cmd)


def tty_save():
    """Remember the terminal settings. The emulator that restore.sh boots can switch
    the terminal to raw mode, which garbles the output and stops Ctrl-C working."""
    try:
        import termios
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        return fd, termios.tcgetattr(fd)
    except Exception:
        return None


def tty_restore(saved):
    if saved:
        try:
            import termios
            termios.tcsetattr(saved[0], termios.TCSANOW, saved[1])
        except Exception:
            pass


def run_restore(cmd, timeout, saved_tty=None):
    """Returns (ok, exit_code, seconds)."""
    t0 = time.time()
    try:
        p = subprocess.run(split_cmd(cmd), timeout=timeout)
        return p.returncode == 0, p.returncode, time.time() - t0
    except subprocess.TimeoutExpired:
        return False, "timeout", time.time() - t0
    except OSError as e:
        return False, "error: %s" % e, time.time() - t0
    finally:
        tty_restore(saved_tty)


def why(impacts, n=3):
    return ", ".join("%s %+.2f" % (f["feature"], f["impact"]) for f in impacts[:n]) or "-"


def main():
    ap = argparse.ArgumentParser(description="Live threat detector + auto-heal trigger")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--input", help="read a finished JSONL file (replay); default is stdin")
    src.add_argument("--follow", help="follow a JSONL file that is still being written")
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--confirm", type=int, default=1, help="consecutive malicious windows before healing")
    ap.add_argument("--restore-cmd", default="./restore.sh", help="Person 1's restore script")
    ap.add_argument("--post-restore-cmd", help="command to run after a successful restore, once the "
                    "grace period starts (e.g. re-apply a runtime setting the reboot reset)")
    ap.add_argument("--restore-timeout", type=float, default=420)
    ap.add_argument("--grace", type=float, default=10, help="extra seconds ignored after a restore")
    ap.add_argument("--max-heals", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true", help="detect and log, never run the restore")
    ap.add_argument("--alerts-only", action="store_true",
                    help="only emit alerts: never restore and never start a cool-down. Use when another "
                         "component (the policy engine) decides the response")
    ap.add_argument("--alerts-out", metavar="PATH",
                    help="append one alert record per scored window to this file the moment it is scored "
                         "(contracts/alert.schema.json). This is the feed for the policy engine")
    ap.add_argument("--online-update", action="store_true",
                    help="let the incremental model keep learning from confident windows")
    ap.add_argument("--save-incremental", metavar="PATH",
                    help="with --online-update: save the updated incremental model here on exit")
    ap.add_argument("--events", default="logs/events.jsonl", help="per-window decision log")
    ap.add_argument("--quiet", action="store_true", help="only print suspicious/malicious windows and heals")
    a = ap.parse_args()

    if HybridModel is not None and os.path.exists(os.path.join(a.model_dir, "multiclass.json")):
        tm = HybridModel.load(a.model_dir)
        print("[%s] hybrid model: binary + anomaly + multi-class + blended risk" % utc(), flush=True)
    else:
        tm = ThreatModel.load(a.model_dir)
    saved_tty = tty_save()
    os.makedirs(os.path.dirname(a.events) or ".", exist_ok=True)
    ev = open(a.events, "a")

    def log(**kw):
        kw["logged_at_epoch"] = round(time.time(), 3)
        ev.write(json.dumps(kw) + "\n"); ev.flush()

    al = None
    if a.alerts_out:
        os.makedirs(os.path.dirname(a.alerts_out) or ".", exist_ok=True)
        al = open(a.alerts_out, "a")

    def emit(rec):
        if al:
            rec = dict({"alert_version": ALERT_VERSION, "emitted_at_epoch": round(time.time(), 3)}, **rec)
            al.write(json.dumps(rec) + "\n"); al.flush()

    def emit_window(rec_in, r, detector_action):
        emit({"type": "window",
              "alert_id": "%s-%.3f" % (rec_in.get("device_ip") or "device", rec_in["window_start_epoch"]),
              "window_id": rec_in.get("window_id"),
              "window_start_epoch": rec_in["window_start_epoch"], "window_end_epoch": rec_in["window_end_epoch"],
              "device_ip": rec_in.get("device_ip", ""), "firmware_id": rec_in.get("firmware_id", ""),
              "interface": rec_in.get("mirror_if", ""),
              "threat_label": r["threat_label"], "threat_probability": r["threat_probability"],
              "risk_score": r["risk_score"],
              "p_xgboost": r["p_xgboost"], "p_incremental": r["p_incremental"],
              "attack_class": r.get("attack_class"),
              "attack_class_prob": r.get("attack_class_prob"),
              "anomaly_score": r.get("anomaly_score"),
              "risk_components": r.get("risk_components"),
              "explanation": [dict(f, monitor=f.get("monitor") or monitor_of(f["feature"])) for f in r["feature_impact"]],
              "fingerprint_schema": tm.schema_version, "detector_action": detector_action})

    lines = lines_file(a.input) if a.input else lines_follow(a.follow) if a.follow else lines_stdin()
    print("[%s] model: schema %s, %d features (%s)" % (
        utc(), tm.schema_version, len(tm.feature_order),
        "network + syscall + energy" if tm.schema_version == "2.0.0" else "network"), flush=True)
    print("[%s] detector up | suspicious >= %.2f, malicious >= %.2f | confirm %d | online-update %s | %s" % (
        utc(), tm.cfg["t_suspicious"], tm.cfg["t_malicious"], a.confirm,
        "on" if a.online_update else "off",
        "ALERTS ONLY (response left to the policy engine)" if a.alerts_only else
        "DRY-RUN (no restore)" if a.dry_run else "restore: " + a.restore_cmd), flush=True)

    streak, heals, resume_after = 0, 0, 0.0
    n = n_mal = n_sus = n_skip = n_bad = n_upd = 0
    try:
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue                      # tolerate log noise mixed into the stream
            try:
                rec = check_record(json.loads(line), tm.schema_version, tm.feature_order)
            except (ValueError, BadRecord) as e:
                n_bad += 1
                print("[%s] skipped bad record: %s" % (utc(), e), file=sys.stderr, flush=True)
                continue

            wid, t0, t1 = rec.get("window_id"), rec["window_start_epoch"], rec["window_end_epoch"]
            if t0 < resume_after:
                n_skip += 1
                log(window_id=wid, window_start_epoch=t0, threat_label="ignored", reason="cooldown")
                if not a.quiet:
                    print("[%s] win %-5s ignored (cool-down after restore)" % (utc(), wid), flush=True)
                continue

            x = to_vector(rec, tm.feature_order)
            r = tm.assess(x)
            lbl, p = r["threat_label"], r["threat_probability"]
            mal = lbl == "malicious"
            n += 1; n_mal += mal; n_sus += lbl == "suspicious"
            streak = streak + 1 if mal else 0
            action = "none"
            if lbl != "benign" or not a.quiet:
                print("[%s] win %-5s %s  p=%.3f (xgb %.2f, inc %.2f)  risk %3d  %-10s%s" % (
                    utc(), wid, utc(t0), p, r["p_xgboost"], r["p_incremental"], r["risk_score"],
                    lbl.upper() if lbl != "benign" else lbl,
                    "  <- " + why(r["feature_impact"]) if lbl != "benign" else ""), flush=True)

            trigger = mal and streak >= a.confirm
            if trigger and a.alerts_only:
                streak = 0
                action = "alert_only"
                emit_window(rec, r, action)
            elif trigger:
                streak = 0
                if heals >= a.max_heals:
                    action = "suppressed_max_heals"
                    emit_window(rec, r, action)
                    print("[%s] !! max heals (%d) reached, not restoring" % (utc(), a.max_heals), flush=True)
                elif a.dry_run:
                    heals += 1
                    action = "would_restore"
                    emit_window(rec, r, action)
                    resume_after = t1 + a.grace
                    print("[%s] >> ATTACK DETECTED - dry-run, restore NOT executed" % utc(), flush=True)
                else:
                    emit_window(rec, r, "restore_started")     # before the restore blocks for minutes
                    print("[%s] >> ATTACK DETECTED - running: %s" % (utc(), a.restore_cmd), flush=True)
                    ok, code, secs = run_restore(a.restore_cmd, a.restore_timeout, saved_tty)
                    heals += 1
                    action = "restored" if ok else "restore_failed"
                    # discard everything captured up to the end of the restore
                    resume_after = t1 + secs + a.grace
                    lag = time.time() - t1       # only meaningful on a live stream, not a replay
                    print("[%s] << %s in %.1f s (exit %s)%s" % (
                        utc(), "DEVICE HEALED" if ok else "RESTORE FAILED", secs, code,
                        "; attack window end -> healed: %.1f s" % lag if 0 <= lag < 3600 else ""), flush=True)
                    log(window_id=wid, event="restore", ok=ok, exit_code=code, restore_seconds=round(secs, 2))
                    emit({"type": "heal", "window_id": wid, "window_end_epoch": t1,
                          "device_ip": rec.get("device_ip", ""), "ok": bool(ok), "exit_code": code,
                          "restore_seconds": round(secs, 2), "ignoring_windows_until_epoch": round(resume_after, 3)})
                    if ok and a.post_restore_cmd:
                        pok, pcode, psecs = run_restore(a.post_restore_cmd, 60, saved_tty)
                        resume_after += psecs
                        print("[%s]    post-restore command %s (exit %s)" % (
                            utc(), "ok" if pok else "FAILED", pcode), flush=True)

            else:
                emit_window(rec, r, "none")

            learned = None
            if a.online_update:
                learned = tm.online_update(x, p)
                n_upd += learned is not None

            log(window_id=wid, window_start_epoch=t0, window_end_epoch=t1,
                p_xgboost=r["p_xgboost"], p_incremental=r["p_incremental"],
                threat_probability=p, threat_label=lbl, risk_score=r["risk_score"],
                feature_impact=r["feature_impact"], action=action,
                online_update_label=learned, manifest_label=rec.get("label"))
    except KeyboardInterrupt:
        pass
    finally:
        tty_restore(saved_tty)
        if al:
            al.close()
        if a.online_update and a.save_incremental:
            dump(tm.inc, a.save_incremental)
        print("[%s] stopped | windows scored %d | malicious %d | suspicious %d | heals %d | "
              "ignored in cool-down %d | bad %d%s" % (
                  utc(), n, n_mal, n_sus, heals, n_skip, n_bad,
                  " | incremental updates %d" % n_upd if a.online_update else ""), flush=True)
        ev.close()


if __name__ == "__main__":
    main()
