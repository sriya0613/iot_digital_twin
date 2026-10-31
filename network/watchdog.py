#!/usr/bin/env python3
"""network/watchdog.py - Person A: is the twin alive? If it dies, heal it.

The detector only looks for attacks. A twin that crashed or froze sends no traffic,
which the detector would happily call benign. This watchdog checks the node itself
every few seconds:

    emulator   the QEMU process is running
    ping       192.168.0.1 answers ping
    http       the router's web page answers (any HTTP status counts)
    bridge     its tap is still a port on br-twin            (reported, not required)
    controller Ryu is connected to br-twin                   (reported, not required)

States:  up -> degraded (a check failed) -> dead (failed N times in a row)
         dead -> healing (runs twin_net.sh heal) -> settling -> up
         dead again and again -> escalated (stops healing, needs a person)

Every change is written to the alert feed (logs/alerts.jsonl) as a record of
type "health", and the current state to network/.state/health.json for the dashboard.

    sudo python3 network/watchdog.py                 run (Ctrl-C to stop)
    sudo python3 network/watchdog.py --status        one check, human readable
    sudo python3 network/watchdog.py --status --json one check, JSON (twin_net.sh status --json)
"""
import argparse
import json
import os
import pwd
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATE = os.path.join(HERE, ".state")
ALERT_VERSION = "1.0.0"


def sh(cmd, timeout=5):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def healing_pid():
    """pid of a heal in progress (twin_net.sh heal writes it), or None."""
    try:
        pid = int(open(os.path.join(STATE, "healing")).read().strip())
        return pid if os.path.exists("/proc/%d" % pid) else None
    except (OSError, ValueError):
        return None


def check(a):
    c = {"emulator": sh("pgrep -f qemu-system-", 3).returncode == 0,
         "ping": sh("ping -c 1 -W 1 %s" % a.ip, 3).returncode == 0}
    if a.http:
        code = sh("curl -s -o /dev/null -m 3 -w '%%{http_code}' http://%s/" % a.ip, 5).stdout.strip()
        c["http"] = code not in ("", "000")
    c["on_bridge"] = sh("ovs-vsctl port-to-br %s" % a.tap, 3).stdout.strip() == a.bridge
    c["controller"] = sh("ovs-vsctl get controller %s is_connected" % a.bridge, 3).stdout.strip() == "true"
    c["healing"] = healing_pid() is not None
    alive = c["emulator"] and c["ping"] and c.get("http", True)
    return c, alive


def run_heal(a):
    t0 = time.time()
    p = sh("bash '%s' heal" % os.path.join(HERE, "twin_net.sh"), a.heal_timeout)
    return p.returncode, round(time.time() - t0, 1), (p.stdout + p.stderr).strip().splitlines()[-1:] or [""]


class Watchdog:
    def __init__(self, a, check_fn=check, heal_fn=run_heal, clock=time.time, sleep=time.sleep, out=print):
        self.a, self.check, self.heal, self.clock, self.sleep, self.out = a, check_fn, heal_fn, clock, sleep, out
        self.state, self.fails, self.heals_in_a_row, self.heals_total = "starting", 0, 0, 0
        self.grace_until, self.up_since, self.controller, self.last_event = 0.0, None, None, None

    # -- output -------------------------------------------------------------
    def emit(self, event, checks, **extra):
        rec = {"alert_version": ALERT_VERSION, "emitted_at_epoch": round(self.clock(), 3), "type": "health",
               "event": event, "device_ip": self.a.ip, "interface": self.a.tap, "state": self.state,
               "checks": checks}
        rec.update(extra)
        self.last_event = rec
        self.out("[%s] %-15s state=%s %s" % (time.strftime("%H:%M:%S"), event, self.state,
                 " ".join("%s=%s" % kv for kv in extra.items())))
        if self.a.alerts_out:
            new = not os.path.exists(self.a.alerts_out)
            os.makedirs(os.path.dirname(self.a.alerts_out) or ".", exist_ok=True)
            with open(self.a.alerts_out, "a") as f:
                f.write(json.dumps(rec) + "\n")
            if new:
                chown_to_user(self.a.alerts_out)

    def save(self, checks):
        if not self.a.health_file:
            return
        d = {"updated_epoch": round(self.clock(), 3), "state": self.state, "checks": checks,
             "consecutive_failed_checks": self.fails, "heals_by_watchdog": self.heals_total,
             "heals_without_recovery": self.heals_in_a_row, "last_event": self.last_event}
        tmp = self.a.health_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, self.a.health_file)

    # -- one step of the state machine -------------------------------------------
    def step(self):
        checks, alive = self.check(self.a)
        now = self.clock()
        failed = [k for k in ("emulator", "ping", "http") if k in checks and not checks[k]]

        ctrl = checks.get("controller")
        if self.controller is not None and ctrl != self.controller:
            self.emit("controller_up" if ctrl else "controller_down", checks)
        self.controller = ctrl

        if checks["healing"]:                       # someone else (the detector) is healing it
            if self.state != "healing":
                self.state = "healing"
                self.emit("heal_in_progress", checks, by="other")
            self.fails = 0
            self.grace_until = now + self.a.grace
        elif now < self.grace_until:
            self.state = "settling"
        elif alive:
            if self.state in ("dead", "escalated", "degraded", "healing", "settling") and self.last_event \
                    and self.last_event["event"] in ("node_dead", "escalate", "heal_ok", "heal_failed", "heal_in_progress"):
                self.state = "up"
                self.emit("node_recovered", checks)
            self.state, self.fails = "up", 0
            self.up_since = self.up_since or now
            if now - self.up_since >= self.a.stable:
                self.heals_in_a_row = 0
        else:
            self.up_since = None
            self.fails += 1
            if self.fails < self.a.fails:
                self.state = "degraded"
            else:
                if self.state not in ("dead", "escalated"):
                    self.state = "dead"
                    self.emit("node_dead", checks, failed_checks=failed, after_checks=self.fails)
                if self.heals_in_a_row >= self.a.max_heals or self.a.no_heal:
                    if self.state != "escalated":
                        self.state = "escalated"
                        self.emit("escalate", checks, reason="no heal" if self.a.no_heal else
                                  "%d heals did not bring the node back for %d s" % (self.heals_in_a_row, self.a.stable))
                else:
                    self.state = "healing"
                    self.save(checks)
                    self.emit("heal_started", checks)
                    rc, secs, tail = self.heal(self.a)
                    self.heals_total += 1
                    self.heals_in_a_row += 1
                    self.state = "settling" if rc == 0 else "dead"
                    self.emit("heal_ok" if rc == 0 else "heal_failed", checks, exit_code=rc,
                              heal_seconds=secs, detail=tail[0][:200])
                    self.fails = 0 if rc == 0 else self.fails
                    self.grace_until = self.clock() + self.a.grace
                    checks, _ = self.check(self.a)          # report the twin as it is after the heal
        self.save(checks)
        return checks

    def run(self):
        self.grace_until = max(self.grace_until, self.clock() + self.a.startup_grace)   # settle first
        self.out("[watchdog] every %ss | dead after %d failed checks | max %d heals without recovery | grace %ss%s"
                 % (self.a.interval, self.a.fails, self.a.max_heals, self.a.grace, " | NO-HEAL" if self.a.no_heal else ""))
        last_beat = 0
        while True:
            prev = self.state
            checks = self.step()
            if self.state != prev or self.clock() - last_beat >= 60:
                self.out("[%s] state=%-9s %s" % (time.strftime("%H:%M:%S"), self.state,
                         " ".join("%s=%s" % (k, "ok" if v else "--") for k, v in checks.items() if k != "healing")))
                last_beat = self.clock()
            self.sleep(self.a.interval)


def chown_to_user(path):
    u = os.environ.get("SUDO_USER")
    if u and os.geteuid() == 0:
        try:
            pw = pwd.getpwnam(u)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        except (KeyError, OSError):
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", default=os.environ.get("DEV_IP", "192.168.0.1"))
    ap.add_argument("--bridge", default=os.environ.get("BR", "br-twin"))
    ap.add_argument("--tap", default="tap%s_0" % os.environ.get("IID", "1"))
    ap.add_argument("--interval", type=float, default=5, help="seconds between checks (5)")
    ap.add_argument("--fails", type=int, default=3, help="failed checks in a row before the node is dead (3)")
    ap.add_argument("--max-heals", type=int, default=2, help="heals without recovery before escalating (2)")
    ap.add_argument("--stable", type=float, default=60, help="seconds up before the heal counter resets (60)")
    ap.add_argument("--grace", type=float, default=30, help="seconds after a heal before checking again (30)")
    ap.add_argument("--startup-grace", type=float, default=90, help="seconds to watch quietly at startup before healing (90)")
    ap.add_argument("--heal-timeout", type=float, default=600)
    ap.add_argument("--no-http", dest="http", action="store_false", help="do not require the web page")
    ap.add_argument("--no-heal", action="store_true", help="report only, never heal")
    ap.add_argument("--alerts-out", default=os.path.join(ROOT, "logs", "alerts.jsonl"))
    ap.add_argument("--health-file", default=os.path.join(STATE, "health.json"))
    ap.add_argument("--status", action="store_true", help="one check and exit (0 = alive)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    os.makedirs(STATE, exist_ok=True)

    if a.status:
        checks, alive = check(a)
        try:
            wd = json.load(open(a.health_file))
            wd_state = wd["state"] if time.time() - wd["updated_epoch"] < 3 * a.interval + 10 else None
        except (OSError, ValueError, KeyError):
            wd_state = None
        flows = sh("ovs-ofctl -O OpenFlow13 dump-flows %s" % a.bridge, 5).stdout
        n_rules = sum(1 for l in flows.splitlines() if "priority=" in l and "priority=0," not in l and "priority=0 " not in l)
        rec = {"checked_epoch": round(time.time(), 3), "device_ip": a.ip, "alive": alive, "checks": checks,
               "containment_rules": n_rules,
               "state": "healing" if checks["healing"] else (wd_state or ("up" if alive else "down")),
               "watchdog_running": wd_state is not None}
        if a.json:
            print(json.dumps(rec))
        else:
            print("alive: %s   state: %s   watchdog running: %s" % (alive, rec["state"], rec["watchdog_running"]))
            for k, v in checks.items():
                print("  %-11s %s" % (k, v))
            print("  containment rules active: %d" % n_rules)
        return 0 if alive else 1

    try:
        Watchdog(a).run()
    except KeyboardInterrupt:
        print("\n[watchdog] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
