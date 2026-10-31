#!/usr/bin/env python3
"""tests/test_watchdog.py - the watchdog's state machine with a fake twin and a fake clock.

    python3 tests/test_watchdog.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "network"))
import watchdog as W  # noqa: E402

fails = 0


def check(name, cond, detail=""):
    global fails
    fails += not cond
    print("%s  %s %s" % ("PASS" if cond else "FAIL", name, detail))


class Twin:
    """alive[t] decides each check; heal() brings it back if heal_works."""
    def __init__(self, heal_works=True):
        self.t, self.alive, self.ctrl, self.heal_works, self.heals = 0.0, True, True, heal_works, 0

    def check(self, a):
        c = {"emulator": self.alive, "ping": self.alive, "http": self.alive,
             "on_bridge": True, "controller": self.ctrl, "healing": False}
        return c, self.alive

    def heal(self, a):
        self.heals += 1
        self.t += 70
        self.alive = self.heal_works
        return (0, 70.0, ["healed"]) if self.heal_works else (3, 70.0, ["not answering"])


def make(twin, **kw):
    tmp = tempfile.mkdtemp()
    args = dict(ip="192.168.0.1", bridge="br-twin", tap="tap1_0", interval=5, fails=3, max_heals=2, stable=60,
                grace=30, heal_timeout=600, http=True, no_heal=False, alerts_out=os.path.join(tmp, "a.jsonl"),
                health_file=os.path.join(tmp, "h.json"))
    args.update(kw)
    ns = type("A", (), args)()
    wd = W.Watchdog(ns, check_fn=twin.check, heal_fn=twin.heal, clock=lambda: twin.t, out=lambda *x: None)
    return wd, ns


def run(wd, twin, seconds):
    end = twin.t + seconds
    while twin.t < end:
        wd.step()
        twin.t += 5


def events(ns):
    return [json.loads(l)["event"] for l in open(ns.alerts_out)] if os.path.exists(ns.alerts_out) else []


# 1. healthy twin: nothing happens
t = Twin(); wd, ns = make(t); run(wd, t, 120)
check("healthy twin: state up, no alerts, no heals", wd.state == "up" and not events(ns) and t.heals == 0)

# 2. twin dies: dead after 3 failed checks, healed once, recovers
t = Twin(); wd, ns = make(t); run(wd, t, 30); t.alive = False; run(wd, t, 15)
ev = events(ns)
check("dead after 3 failed checks, then healed", ev[:3] == ["node_dead", "heal_started", "heal_ok"] and t.heals == 1, str(ev))
run(wd, t, 60)
check("recovers after the grace period", events(ns)[-1] == "node_recovered" and wd.state == "up", str(events(ns)))
t2 = Twin(); wd2, ns2 = make(t2); run(wd2, t2, 10); t2.alive = False; wd2.step(); st = wd2.state; t2.alive = True; t2.t += 5; wd2.step()
check("a single missed check does not heal", st == "degraded" and wd2.state == "up" and t2.heals == 0 and not events(ns2))

# 3. heals that do not work: escalates after 2, stops healing
t = Twin(heal_works=False); wd, ns = make(t); t.alive = False; run(wd, t, 400)
ev = events(ns)
check("escalates after 2 failed heals and stops healing", t.heals == 2 and "escalate" in ev and wd.state == "escalated", str(ev))
t.alive = True; run(wd, t, 10)
check("escalated twin brought back by hand -> recovered", events(ns)[-1] == "node_recovered" and wd.state == "up")

# 4. --no-heal: report only
t = Twin(); wd, ns = make(t, no_heal=True); t.alive = False; run(wd, t, 30)
check("--no-heal reports dead + escalate, never heals", t.heals == 0 and events(ns)[:2] == ["node_dead", "escalate"])

# 5. controller down/up is reported
t = Twin(); wd, ns = make(t); run(wd, t, 10); t.ctrl = False; run(wd, t, 10); t.ctrl = True; run(wd, t, 10)
check("controller_down / controller_up reported once each", events(ns) == ["controller_down", "controller_up"], str(events(ns)))

# 6. records validate against the contract, health file written
try:
    import jsonschema
    S = json.load(open(os.path.join(ROOT, "contracts", "alert.schema.json")))
    t = Twin(heal_works=False); wd, ns = make(t); t.alive = False; run(wd, t, 400)
    for l in open(ns.alerts_out):
        jsonschema.validate(json.loads(l), S)
    check("health records validate against contracts/alert.schema.json", True)
except ImportError:
    print("SKIP  schema validation (pip install jsonschema)")
h = json.load(open(ns.health_file))
check("health.json written for the dashboard", h["state"] == wd.state and "checks" in h)

print("\n%s" % ("ALL WATCHDOG TESTS PASSED" if not fails else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
