#!/usr/bin/env python3 -I
"""test_verify_heal.py — persond/verify_heal.py and its optional use in the healing engine.

No twin, no network, no waiting: probes are fakes and time is simulated.
The engine runs the real tests/fake_restore.py as its restore command.

  python3 -I -m pytest tests/test_verify_heal.py -v
"""
import json
import os
import sqlite3
import sys

import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "persond"))
import verify_heal as vh  # noqa: E402
from containment import COOKIE_ISOLATE  # noqa: E402
from healing_engine import HealingEngine  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeNet:
    def __init__(self, flows=()):
        self.mode, self.flows = "ryu", list(flows)

    def _flows(self):
        return self.flows


def restore_record(tmp_path, disk="abc", registered="abc", age=60, name="last_restore.json"):
    rec = tmp_path / name
    rec.write_text(json.dumps({"copied_at_epoch": 10000 - age, "disk_sha256": disk, "registered_sha256": registered}))
    return str(rec)


def make(tmp_path, registry_hash="abc", image_hash="abc", **kw):
    img = tmp_path / "image.baseline.raw"; img.write_bytes(b"x")
    reg = tmp_path / "baseline.sha256"
    if registry_hash is not None:
        reg.write_text(registry_hash + "  image\n")
    clk = Clock()
    args = dict(containment=FakeNet(), baseline_image=str(img), registry=str(reg), hasher=lambda p: image_hash,
                ping=lambda ip: True, http=lambda ip: 200, clock=clk.now, sleep=clk.sleep,
                restore_record=restore_record(tmp_path), wall=lambda: 10000)
    args.update(kw)
    return vh.HealVerifier(**args), clk


def factor(r, name):
    return next(c for c in r["checks"] if c["factor"] == name)


# ------------------------------------------------------------------ verifier
def test_all_checks_pass(tmp_path):
    v, _ = make(tmp_path, client_cmd="true", run=lambda c: True)
    r = v.verify("192.168.0.1")
    assert r["ok"] and r["failed"] == [] and r["skipped"] == []


def test_boot_waits_then_times_out_on_simulated_clock(tmp_path):
    v, clk = make(tmp_path, ping=lambda ip: False, http=lambda ip: None)
    r = v.verify("192.168.0.1")
    assert not r["ok"] and set(r["failed"]) == {"boot", "service"}
    assert factor(r, "boot")["detail"] == "no ping answer within 60 s"
    assert clk.t >= 60 + 90                                 # waited the full timeouts, in simulated time


def test_boot_succeeds_after_delay(tmp_path):
    v, clk = make(tmp_path)
    v.ping = lambda ip: clk.t >= 20                          # twin answers after 20 s
    assert v.check_boot("x")["ok"] is True and 20 <= clk.t < 30


def test_http_code_filter(tmp_path):
    v, _ = make(tmp_path, http=lambda ip: 403, accept_http=[200, 302])
    c = v.check_service("x")
    assert c["ok"] is False and "403" in c["detail"]
    v2, _ = make(tmp_path, http=lambda ip: 403)                # default: any HTTP answer counts
    assert v2.check_service("x")["ok"] is True


def test_baseline_mismatch_fails_and_missing_registry_is_skipped(tmp_path):
    v, _ = make(tmp_path, registry_hash="abc", image_hash="def")
    assert v.check_baseline()["ok"] is False
    v2, _ = make(tmp_path / "..", registry_hash=None)
    r = v2.verify("x")
    assert "baseline" in r["skipped"] and "baseline" not in r["failed"] and r["ok"]


def test_leftover_containment_rule_fails_network(tmp_path):
    v, _ = make(tmp_path, containment=FakeNet([{"cookie": COOKIE_ISOLATE}, {"cookie": 0}]))
    c = v.check_network()
    assert c["ok"] is False and "1 containment rule" in c["detail"]


def test_print_mode_network_is_not_checked(tmp_path):
    class PrintNet:
        mode = "print"
    v, _ = make(tmp_path, containment=PrintNet())
    assert v.check_network()["ok"] is None


def test_broken_probe_is_a_failure_not_a_pass(tmp_path):
    def boom(ip):
        raise RuntimeError("socket exploded")
    v, _ = make(tmp_path, ping=boom)
    c = v.check_boot("x")
    assert c["ok"] is False and "socket exploded" in c["detail"]


def test_register_baseline_writes_hash(tmp_path):
    img = tmp_path / "img"; img.write_bytes(b"hello")
    reg = tmp_path / "s" / "baseline.sha256"
    h = vh.register_baseline(str(img), str(reg))
    assert h == vh.sha256_file(str(img)) and reg.read_text().split()[0] == h


def test_http_status_ignores_proxy_env(monkeypatch):
    """A system proxy must not answer for the twin (the cloud workspace's proxy returned 403)."""
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    assert vh.http_status("127.0.0.1", timeout=1) is None    # nothing listens on :80 locally, so no answer at all


def test_disk_check_matches_recorded_restore(tmp_path):           # IMP-05
    v, _ = make(tmp_path)
    assert factor(v.verify("192.168.0.1"), "disk")["ok"] is True


def test_disk_check_fails_on_wrong_hash_or_old_record(tmp_path):
    v, _ = make(tmp_path, restore_record=restore_record(tmp_path, disk="evil", name="evil.json"))
    assert factor(v.verify("192.168.0.1"), "disk")["ok"] is False
    v, _ = make(tmp_path, restore_record=restore_record(tmp_path, age=3600, name="old.json"))
    r = factor(v.verify("192.168.0.1"), "disk")
    assert r["ok"] is False and "old" in r["detail"]


def test_disk_check_skipped_without_record(tmp_path):
    v, _ = make(tmp_path, restore_record=str(tmp_path / "none.json"))
    assert factor(v.verify("192.168.0.1"), "disk")["ok"] is None


def inode_record(tmp_path, before=11, after=12, age=60, name="inode.json"):
    rec = tmp_path / name
    rec.write_text(json.dumps({"method": "inode", "finished_epoch": 10000 - age, "inode_before": before,
                               "inode_after": after, "replaced": before != after, "restore_rc": "0"}))
    return str(rec)


def test_disk_check_inode_replaced(tmp_path):                    # IMP-05 v2 (twin_net.sh heal record)
    v, _ = make(tmp_path, restore_record=inode_record(tmp_path))
    r = factor(v.verify("192.168.0.1"), "disk")
    assert r["ok"] is True and "replaced" in r["detail"]


def test_disk_check_inode_not_replaced_fails(tmp_path):
    v, _ = make(tmp_path, restore_record=inode_record(tmp_path, before=12, after=12, name="same.json"))
    assert factor(v.verify("192.168.0.1"), "disk")["ok"] is False


def test_disk_is_checked_before_release():
    assert "disk" in vh.HealVerifier.WHILE_ISOLATED


# ------------------------------------------------------------------ engine integration
def win(t, risk):
    label = "benign" if risk < 15 else "suspicious" if risk < 35 else "malicious"
    return {"alert_version": "1.0.0", "type": "window", "emitted_at_epoch": t + 5.1,
            "alert_id": "192.168.0.1-%.3f" % t, "window_start_epoch": t, "window_end_epoch": t + 5,
            "device_ip": "192.168.0.1", "threat_label": label, "threat_probability": risk / 100,
            "risk_score": risk, "explanation": [{"feature": "n_unique_dst_ports", "value": 1,
                                                 "impact": 3, "direction": "raises risk"}],
            "detector_action": "alert_only"}


class StubVerifier:
    """ok: result of the checks done while isolated; ok_after: result of those done after release."""
    WHILE_ISOLATED, AFTER_RELEASE = vh.HealVerifier.WHILE_ISOLATED, vh.HealVerifier.AFTER_RELEASE

    def __init__(self, ok, ok_after=True):
        self.ok, self.ok_after, self.calls = ok, ok_after, 0

    def verify(self, ip, factors=None):
        self.calls += 1
        if factors == self.AFTER_RELEASE:
            ok, name = self.ok_after, "client"
            checks = [{"factor": "client", "ok": ok, "detail": "stub", "seconds": 0.0}]
            return {"ok": ok, "failed": [] if ok else [name], "skipped": [], "checks": checks}
        checks = [{"factor": "boot", "ok": self.ok, "detail": "stub", "seconds": 0.0},
                  {"factor": "baseline", "ok": None, "detail": "not registered", "seconds": 0.0}]
        return {"ok": self.ok, "failed": [] if self.ok else ["boot"], "skipped": ["baseline"], "checks": checks}


def heal_then_calm(tmp_path, verifier, name):
    os.environ["FAKE_RESTORE_LOG"] = str(tmp_path / "restore.log")
    db = ThreatDatabase(str(tmp_path / (name + ".db")))
    eng = HealingEngine(db, grace=30, verifier=verifier)
    out = [eng.handle(win(1000, 95))]                          # quarantine -> fake restore -> (checks)
    out += [eng.handle(win(t, 5)) for t in (1100, 1105, 1110, 1115)]   # calm windows after grace
    con = sqlite3.connect(str(tmp_path / (name + ".db")))
    status = con.execute("SELECT verify_status FROM heals").fetchone()[0]
    checks = con.execute("SELECT factor, ok FROM heal_checks").fetchall()
    notes = con.execute("SELECT kind, reason FROM escalations").fetchall()
    return out, status, checks, notes


def test_engine_without_verifier_is_unchanged(tmp_path):
    out, status, checks, notes = heal_then_calm(tmp_path, None, "plain")
    assert out[0] == "restored" and status == "verified" and checks == [] and notes == []


def test_engine_with_passing_checks_verifies(tmp_path):
    v = StubVerifier(True)
    out, status, checks, notes = heal_then_calm(tmp_path, v, "pass")
    assert v.calls == 2 and status == "verified"                # before release + after release
    assert sorted(checks) == [("baseline", None), ("boot", 1), ("client", 1)] and notes == []


def test_engine_with_failed_check_keeps_isolation_and_holds(tmp_path):   # IMP-06: was release + notify
    v = StubVerifier(False)
    out, status, checks, notes = heal_then_calm(tmp_path, v, "fail")
    assert out[0] == "restored_checks_failed" and status == "failed"
    assert ("boot", 0) in checks and v.calls == 1               # after-release checks never ran
    assert notes and notes[-1][0] == "hold" and "boot" in notes[-1][1]
    assert set(out[1:]) == {"held"}                             # later alerts: held, no auto-reset


# ------------------------------------------------------------------ Member 2 fixes (IMP-06/08/09, E11 retry)
class RecNet:
    """Containment double: records calls; isolate can be made to fail the first n times (Ryu down)."""
    def __init__(self, fail_isolate=0):
        self.mode, self.calls, self.fail_isolate = "ryu", [], fail_isolate

    def _res(self, ok):
        return {"ok": ok, "verified": ok, "seconds": 0.01, "detail": "stub"}

    def isolate(self, dev):
        self.calls.append("isolate")
        if self.fail_isolate > 0:
            self.fail_isolate -= 1
            return self._res(False)
        return self._res(True)

    def release(self, dev):
        self.calls.append("release")
        return self._res(True)

    def rate_limit(self, dev):
        self.calls.append("rate_limit"); return self._res(True)

    def unlimit(self, dev):
        self.calls.append("unlimit"); return self._res(True)


def engine(tmp_path, name, net, verifier=None):
    os.environ["FAKE_RESTORE_LOG"] = str(tmp_path / "restore.log")
    db = ThreatDatabase(str(tmp_path / (name + ".db")))
    return HealingEngine(db, containment=net, grace=30, verifier=verifier, sleep=lambda s: None), db


def test_failed_check_never_releases(tmp_path):
    net = RecNet()
    eng, _ = engine(tmp_path, "norel", net, StubVerifier(False))
    assert eng.handle(win(1000, 95)) == "restored_checks_failed"
    assert net.calls == ["isolate"]                             # isolated, never released


def test_after_release_failure_isolates_again_and_holds(tmp_path):
    net = RecNet()
    eng, db = engine(tmp_path, "after", net, StubVerifier(True, ok_after=False))
    assert eng.handle(win(1000, 95)) == "restored_checks_failed"
    assert net.calls == ["isolate", "release", "isolate"]
    assert "client" in db.held_reason("192.168.0.1")


def test_reinfection_isolates_and_holds(tmp_path):              # IMP-08: was only recorded
    net = RecNet()
    eng, db = engine(tmp_path, "reinf", net)
    assert eng.handle(win(1000, 95)) == "restored"
    out = [eng.handle(win(t, 95)) for t in (1100, 1105)]        # two high windows after grace
    assert out == ["verifying_high", "reinfected_held"]         # first one waits, no second restore
    assert net.calls[-1] == "isolate" and "reinfected" in db.held_reason("192.168.0.1")


def watchdog_heal(t):
    return {"alert_version": "1.0.0", "type": "health", "event": "heal_ok", "emitted_at_epoch": t,
            "device_ip": "192.168.0.1", "exit_code": 0, "heal_seconds": 70.0}


def test_watchdog_heals_count_toward_hold(tmp_path):            # IMP-09
    net = RecNet()
    eng, db = engine(tmp_path, "wd", net)
    assert eng.handle(watchdog_heal(1000)) == "watchdog_heal"
    assert eng.handle(watchdog_heal(1200)) == "watchdog_heal"
    assert eng.handle(watchdog_heal(1400)) == "watchdog_heal_held"   # 3 within 10 min
    assert db.held_reason("192.168.0.1") and net.calls == ["isolate"]
    assert db.count("heals") == 3


def test_failed_isolate_is_retried_until_it_works(tmp_path):    # E11: Ryu down during isolate
    net = RecNet(fail_isolate=2)                                # Ryu comes back during the retry
    eng, db = engine(tmp_path, "retry", net)
    db.escalate("192.168.0.1", "hold", "restore failed", 890)    # held, and its isolate had failed
    eng.pending_isolate.add("192.168.0.1")
    assert eng.handle(win(900, 5)) == "held"                    # retry: 2 more failures, then it works
    assert "192.168.0.1" not in eng.pending_isolate and "192.168.0.1" in eng.isolated
    assert net.calls.count("release") == 0


def test_failed_isolate_notifies_and_stays_pending(tmp_path):
    net = RecNet(fail_isolate=100)
    eng, db = engine(tmp_path, "pend", net)
    eng.restore_cmd = ["false"]                                 # restore fails too -> held, isolate still owed
    assert eng.handle(win(1000, 95)) == "restore_failed"
    assert "192.168.0.1" in eng.pending_isolate and db.held_reason("192.168.0.1")
    assert any("isolate failed" in r[0] for r in db.rows("SELECT reason FROM escalations"))
    eng.handle(win(1100, 5))                                    # every new record retries
    assert net.calls.count("isolate") == 6


# ------------------------------------------------------------------ IMP-11: state survives an engine restart
def test_interrupted_restore_is_held_and_isolated_by_next_engine(tmp_path):
    net = RecNet()
    eng, db = engine(tmp_path, "crash", net)
    db.set_stage("192.168.0.1", "restoring", 1000, "trigger risk 95")   # as left by an engine killed mid-restore
    eng2, _ = engine(tmp_path, "crash", RecNet())                        # a new engine on the same db
    assert "restore" in db.held_reason("192.168.0.1")
    assert eng2.net.calls == ["isolate"] and "192.168.0.1" in eng2.isolated
    assert db.stages() == []
    assert eng2.handle(win(2000, 5)) == "held"                          # calm alerts do not release it


def test_held_device_is_isolated_again_on_start(tmp_path):
    eng, db = engine(tmp_path, "held", RecNet())
    db.escalate("192.168.0.1", "hold", "3 heals within 10 min", 1000)
    eng2, _ = engine(tmp_path, "held", RecNet())
    assert eng2.net.calls == ["isolate"]


def test_finished_restore_leaves_no_stage(tmp_path):
    eng, db = engine(tmp_path, "done", RecNet())
    assert eng.handle(win(1000, 95)) == "restored"
    assert db.stages() == []


def test_pipeline_stop_does_not_release(tmp_path):
    import subprocess
    feed = tmp_path / "a.jsonl"
    feed.write_text(json.dumps(win(1000, 95)) + "\n")
    out = subprocess.run([sys.executable, os.path.join(ROOT, "persond", "run_pipeline.py"), str(feed),
                          "--db", str(tmp_path / "p.db"), "--restore-cmd", "false"],
                         capture_output=True, text=True, timeout=60).stdout
    assert "restore FAILED" in out and "would release" not in out
    assert "containment left in place for 192.168.0.1" in out


def test_restore_failing_mid_copy_keeps_isolation_and_holds(tmp_path):   # IMP-18 / SYS-08
    """A restore that dies part-way (e.g. cp interrupted, disk full) exits non-zero: the device must stay
    isolated, be held for a human, and not be released by later calm alerts."""
    script = tmp_path / "restore_dies.sh"
    script.write_text("#!/bin/sh\necho copying...; exit 1\n")
    net = RecNet()
    eng, db = engine(tmp_path, "midcopy", net)
    eng.restore_cmd = ["sh", str(script)]
    assert eng.handle(win(1000, 95)) == "restore_failed"
    assert "restore failed" in db.held_reason("192.168.0.1")
    assert [eng.handle(win(t, 5)) for t in (1100, 1105)] == ["held", "held"]
    assert "release" not in net.calls


# ------------------------------------------------------------------ IMP-10: restore in the background
def test_background_restore_keeps_deciding(tmp_path):
    import time as _t
    script = tmp_path / "slow_restore.sh"
    script.write_text("#!/bin/sh\nsleep 1.5\nexit 0\n")
    net = RecNet()
    eng, db = engine(tmp_path, "bg", net)
    eng.background, eng.restore_cmd = True, ["sh", str(script)]
    t0 = _t.time()
    assert eng.handle(win(1000, 95)) == "restoring"             # returns at once, restore runs on
    other = dict(win(1001, 50), device_ip="192.168.0.9", alert_id="other-1001")
    assert eng.handle(other) == "rate_limit"                     # another device is decided meanwhile
    assert eng.handle(win(1005, 95)) == "ignored"                # the restoring device's alerts wait
    assert _t.time() - t0 < 1.0                                  # nothing above waited for the restore
    assert eng.collect(wait=True) == ["restored"]
    assert net.calls[:2] == ["isolate", "rate_limit"] and "release" in net.calls
    assert db.stages() == []


def test_background_restore_failure_is_held(tmp_path):
    net = RecNet()
    eng, db = engine(tmp_path, "bgfail", net)
    eng.background, eng.restore_cmd = True, ["false"]
    assert eng.handle(win(1000, 95)) == "restoring"
    assert eng.collect(wait=True) == ["restore_failed"]
    assert "restore failed" in db.held_reason("192.168.0.1") and "release" not in net.calls
