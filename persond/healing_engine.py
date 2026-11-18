#!/usr/bin/env python3
"""healing_engine.py - Graded, Verified Rollback, with containment and escalation.

The same steps for every alert (see Self-Healing_Approach_Graded_Verified_Rollback.pdf):

  1. Decide        policy engine: risk > 70 -> heal, 30-70 -> rate-limit, < 30 -> watch.
                   A device escalated in the last hour is treated strictly: heal above 50.
                   (diagram: Escalate Policy -> Policy Engine feedback)
  2. No double-heal  while a reset runs, or until GRACE (30 s) after it, the device's alerts are ignored.
                   If the detector is already resetting the device itself, we do not reset it again.
  3. Reset         isolate (containment.py: Ryu drop rule + rule verification) -> run the restore
                   command and wait -> release
  4. Verify        the next VERIFY_WINDOWS (3) alerts after the grace period must all score <= 70
                   -> heal 'verified'. A high score in that time -> 'reinfected'.
                   No verdict within 2 min after the grace period -> 'unverified'.
  5. Escalate      'hold'   : 3 heals within 10 min (counted from the last human clear), or a failed reset
                              -> stop auto-reset, keep the device isolated, hold it for a human.
                   'notify' : stuck in the rate-limit band for 2 min, or a containment rule that could
                              not be verified -> tell a human, keep going (and policy becomes strict).
                   Clear a held device with:  python persond/healing_engine.py --clear 192.168.0.1
                   (or the Clear button on the dashboard)
  6. Record        every alert, action, heal, escalation, containment step and indicator -> threat.db

Only one reset runs at a time: the restore command is waited for before the next alert is read.
Times are on the ALERT clock (window times in the feed), so replays at full speed behave correctly.

  python persond/healing_engine.py samples/SYNTHETIC_risk_ladder.jsonl
  python persond/healing_engine.py --status
  python persond/healing_engine.py --clear 192.168.0.1
"""
import os
import subprocess
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402
from containment import Containment  # noqa: E402
from policy import decide, OBSERVE, RATE_LIMIT, QUARANTINE, QUARANTINE_ABOVE  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_RESTORE = [sys.executable, os.path.join(HERE, "..", "tests", "fake_restore.py")]

GRACE_SECONDS = int(os.environ.get("HEAL_GRACE", "90"))   # ignore a device this long after its reset finished (firmware boot settles slowly)
VERIFY_WINDOWS = 3          # this many low-risk alerts after the grace period = heal verified
VERIFY_DEADLINE = 120       # verification must finish within 2 min after the grace period, else 'unverified'
REINFECT_ABOVE = int(os.environ.get("HEAL_REINFECT_ABOVE", "80"))   # reinfection only above this (boot traffic can briefly hit ~72)
REINFECT_STREAK = int(os.environ.get("HEAL_REINFECT_STREAK", "2"))  # and only if this many in a row are high
MAX_HEALS = 3               # this many heals ...
ESCALATE_WINDOW = 600       # ... within 10 minutes -> hold for a human
RATE_LIMIT_ESCALATE = 120   # rate-limited this long without going back to normal -> notify a human
STRICT_FOR = 3600           # after an escalation, the policy is strict for this device for 1 hour
WAIT_FOR_DETECTOR = 600     # detector is resetting: ignore until its heal record arrives (max 10 min)


class HealingEngine:
    def __init__(self, db, restore_cmd=None, containment=None, grace=GRACE_SECONDS, max_heals=MAX_HEALS,
                 escalate_window=ESCALATE_WINDOW, verify_windows=VERIFY_WINDOWS, verifier=None):
        self.db = db
        self.verifier = verifier  # optional verify_heal.HealVerifier; None = window-based verification only (default)
        self.restore_cmd = restore_cmd or FAKE_RESTORE
        self.net = containment or Containment("print")
        self.grace = grace
        self.max_heals = max_heals
        self.escalate_window = escalate_window
        self.verify_windows = verify_windows
        self.ignore = {}          # device -> (from, until) on the alert clock
        self.verifying = {}       # device -> {"heal_id", "clean", "healed_at"}
        self.rate_limited = {}    # device -> alert-clock time the current rate-limit started
        self.rate_notified = set()
        self.isolated = set()     # devices we currently hold isolated
        self.escalated = []       # (device, reason) - this run only; the database keeps all of them

    # ---- containment (diagram: SDN Controller -> Traffic Containment -> Rule Verification) ----
    def _contain(self, what, dev, at):
        res = getattr(self.net, what)(dev)
        self.db.record_containment(dev, what, self.net.mode, res["ok"], res["verified"], res["seconds"], at, res["detail"])
        if self.net.mode == "ryu" and not (res["ok"] and res["verified"]):
            self.notify(dev, "%s rule not confirmed on the switch (%s)" % (what, res["detail"]), at)
        return res

    # ---- escalation ------------------------------------------------------------------------
    def hold(self, dev, reason, at):
        """Stop auto-resetting this device and hold it (isolated) for a human."""
        self.escalated.append((dev, reason))
        self.db.escalate(dev, "hold", reason, at)
        print("    -> ESCALATE %s: %s. Auto-reset stopped, device stays isolated until a human clears it." % (dev, reason))

    def notify(self, dev, reason, at):
        """Tell a human; nothing is stopped. Makes the policy strict for this device for an hour."""
        self.escalated.append((dev, reason))
        self.db.escalate(dev, "notify", reason, at)
        print("    -> NOTIFY human about %s: %s" % (dev, reason))

    def strict(self, dev, now):
        return self.db.escalated_since(dev, now - STRICT_FOR, now) > 0

    def too_many_heals(self, dev, now):
        since = max(now - self.escalate_window, self.db.cleared_at(dev) + 0.001)   # a clear starts a fresh count
        n = self.db.heals_between(dev, since, now)
        return n >= self.max_heals, n

    # ---- verification ----------------------------------------------------------------------
    def start_verify(self, dev, heal_id, healed_at, checks_ok=True, failed=()):
        if heal_id is not None:
            self.verifying[dev] = {"heal_id": heal_id, "clean": 0, "hi": 0, "healed_at": healed_at,
                                   "checks_ok": checks_ok, "failed": list(failed)}

    def check_verify(self, dev, a):
        """Called for each alert that arrives after the grace period. Returns True if reinfected."""
        v = self.verifying.get(dev)
        if not v or a["window_start_epoch"] < v["healed_at"]:
            return False                                  # no heal to verify, or an alert from before the heal
        if a["window_start_epoch"] > v["healed_at"] + self.grace + VERIFY_DEADLINE:
            self.db.set_verify(v["heal_id"], "unverified")   # too few alerts arrived in time to judge
            del self.verifying[dev]
            print("[verify] %s heal UNVERIFIED: not enough alerts within %d s after the grace period" % (dev, VERIFY_DEADLINE))
            return False
        if a["risk_score"] > REINFECT_ABOVE:
            v["hi"] = v.get("hi", 0) + 1
            if v["hi"] < REINFECT_STREAK:
                return False                              # one noisy boot window - wait for the next before judging
            self.db.set_verify(v["heal_id"], "reinfected")
            del self.verifying[dev]
            print("[verify] %s REINFECTED: %d windows > %d after the heal" % (dev, REINFECT_STREAK, REINFECT_ABOVE))
            return True
        v["clean"] += 1
        v["hi"] = 0                                        # a calm window breaks the reinfection streak
        if v["clean"] >= self.verify_windows:
            del self.verifying[dev]
            if v.get("checks_ok", True):
                self.db.set_verify(v["heal_id"], "verified")
                print("[verify] %s heal VERIFIED: %d low-risk windows after the reset" % (dev, self.verify_windows))
            else:   # low-risk windows alone are not enough when an independent check failed
                self.db.set_verify(v["heal_id"], "unverified")
                print("[verify] %s heal UNVERIFIED: windows were low-risk but checks failed: %s"
                      % (dev, ", ".join(v.get("failed", []))))
        return False

    # ---- main entry ------------------------------------------------------------------------
    def handle(self, a):
        """Process one record from the feed. Returns what was done (a short string)."""
        dev = a.get("device_ip") or "device"

        if a["type"] == "health":                        # Person A's watchdog
            self.db.record_health(a)
            return "health"

        if a["type"] == "heal":                          # the detector reset the device itself
            done = a["emitted_at_epoch"]
            heal_id = self.db.record_heal(a, source="detector")
            self.ignore[dev] = (a.get("window_end_epoch", done - a["restore_seconds"]), done + self.grace)
            print("[heal]  detector restored %s ok=%s in %.0f s; ignoring it for %d s more"
                  % (dev, a["ok"], a["restore_seconds"], self.grace))
            if a["ok"]:
                self.start_verify(dev, heal_id, done)
            return "detector_heal"

        if not self.db.insert_alert(a):
            return "duplicate"
        now = a["window_end_epoch"]

        # a held device is not auto-reset again, and stays isolated
        held = self.db.held_reason(dev)
        if held:
            self.db.record_action(a, "held", "held for a human: " + held)
            if a["risk_score"] > QUARANTINE_ABOVE:
                print("[risk %3d] %s is held for a human (%s) - not resetting" % (a["risk_score"], dev, held))
            return "held"
        if dev in self.isolated:                          # a human cleared it since: lift the isolation
            print("[clear] %s was cleared by a human" % dev)
            self._contain("release", dev, now)
            self.isolated.discard(dev)

        # no double-heal
        start, until = self.ignore.get(dev, (0, 0))
        if start <= a["window_start_epoch"] < until:
            self.db.record_action(a, "ignored", "device restoring or in %d s grace" % self.grace)
            print("[risk %3d] ignored - %s is restoring / in grace period" % (a["risk_score"], dev))
            return "ignored"

        # verify the last heal
        self.check_verify(dev, a)

        # decide (strict if the device was escalated in the last hour)
        action, reason = decide(a, strict=self.strict(dev, now))

        if action != RATE_LIMIT and dev in self.rate_limited:   # back to normal (or worse): lift the rate-limit
            self._contain("unlimit", dev, now)
            del self.rate_limited[dev]
            self.rate_notified.discard(dev)

        if action == OBSERVE:
            self.db.record_action(a, action, reason)
            return action

        print("[risk %3d] %s -> %s  (%s)" % (a["risk_score"], a["threat_label"], action.upper(), reason))
        self.db.record_indicators(a)

        if action == RATE_LIMIT:
            self.db.record_action(a, action, reason)
            if dev not in self.rate_limited:
                self.rate_limited[dev] = a["window_start_epoch"]
                self._contain("rate_limit", dev, now)
            elif now - self.rate_limited[dev] >= RATE_LIMIT_ESCALATE and dev not in self.rate_notified:
                self.rate_notified.add(dev)
                self.notify(dev, "rate-limited for %d s without returning to normal" % (now - self.rate_limited[dev]), now)
            return action

        # quarantine
        if a["detector_action"] == "restore_started":
            print("    (the detector is already restoring %s - not starting a second restore)" % dev)
            self.ignore[dev] = (a["window_end_epoch"], a["window_end_epoch"] + WAIT_FOR_DETECTOR)
            self.db.record_action(a, QUARANTINE, reason + "; restore left to detector")
            return "left_to_detector"

        self.db.record_action(a, QUARANTINE, reason)
        self._contain("isolate", dev, now)
        self.isolated.add(dev)

        # reset
        print("    -> running restore: %s" % " ".join(self.restore_cmd))
        t0 = time.time()
        try:
            exit_code = subprocess.call(self.restore_cmd)     # blocks: only one restore at a time
        except OSError as e:                                  # restore command missing
            exit_code = "not run: %s" % e
        secs = round(time.time() - t0, 2)
        ok = exit_code == 0
        done = now + secs
        heal_id = self.db.record_heal({"device_ip": dev, "ok": ok, "exit_code": exit_code, "restore_seconds": secs,
                                       "window_end_epoch": now, "emitted_at_epoch": done},
                                      source="healing_engine", trigger_risk=a["risk_score"])
        self.ignore[dev] = (now, done + self.grace)
        if not ok:
            print("    -> restore FAILED (exit %s) after %.1f s" % (exit_code, secs))
            self.hold(dev, "restore failed (exit %s)" % exit_code, done)
            return "restore_failed"

        print("    -> restored OK in %.1f s; ignoring %s for %d s, then verifying" % (secs, dev, self.grace))
        over, n = self.too_many_heals(dev, done)
        if over:
            self.hold(dev, "%d heals within %d min" % (n, self.escalate_window // 60), done)
            return "restored_then_held"
        self._contain("release", dev, done)
        self.isolated.discard(dev)
        checks_ok, failed = True, []
        if self.verifier is not None and heal_id is not None:
            r = self.verifier.verify(dev)                     # read-only checks; blocks like the restore does
            self.db.record_heal_checks(heal_id, r)
            checks_ok, failed = r["ok"], r["failed"]
            print("    -> independent checks: %s%s" % ("all passed" if checks_ok else "FAILED " + ", ".join(failed),
                                                    " (not checked: %s)" % ", ".join(r["skipped"]) if r["skipped"] else ""))
            if not checks_ok:
                self.notify(dev, "heal checks failed: %s" % ", ".join(failed), done)
        self.start_verify(dev, heal_id, done, checks_ok, failed)
        return "restored"


def main():
    args = sys.argv[1:]
    db = ThreatDatabase(os.environ.get("THREAT_DB", "threat.db"))
    if args[:1] == ["--clear"] and len(args) == 2:
        if db.clear(args[1], by="command line"):
            print("cleared %s: auto-reset is on again; the running engine lifts its isolation on the next alert" % args[1])
        else:
            print("%s was not held" % args[1])
        return
    if args == ["--status"]:
        held = db.rows("SELECT device_ip, reason FROM device_state WHERE status = 'held'")
        print("devices held for a human:", held if held else "none")
        for r in db.rows("SELECT device_ip, trigger_risk, ok, restore_seconds, source, verify_status FROM heals "
                         "ORDER BY emitted_at_epoch"):
            print("  heal %s trigger risk %s ok=%s %.1f s (%s) -> %s" % (r[0], r[1], bool(r[2]), r[3], r[4], r[5]))
        for r in db.rows("SELECT device_ip, kind, reason, cleared_by FROM escalations ORDER BY at_epoch"):
            print("  escalation %s %s: %s%s" % (r[0], r[1], r[2], "  (cleared by %s)" % r[3] if r[3] else ""))
        return
    eng = HealingEngine(db)
    src = open(args[0]) if args else sys.stdin
    c = Counter(eng.handle(a) for a in read_alerts(src))
    print("\nsummary:", dict(c))
    if eng.escalated:
        print("escalations:", eng.escalated)


if __name__ == "__main__":
    main()
