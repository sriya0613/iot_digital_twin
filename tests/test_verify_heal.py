#!/usr/bin/env python3 -I
"""test_verify_heal.py — persond/verify_heal.py and its optional use in the healing engine.

No twin, no network, no waiting: probes are fakes and time is simulated.
The engine runs the real tests/fake_restore.py as its restore command.

  python3 -I -m pytest tests/test_verify_heal.py -v
"""
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


def make(tmp_path, registry_hash="abc", image_hash="abc", **kw):
    img = tmp_path / "image.baseline.raw"; img.write_bytes(b"x")
    reg = tmp_path / "baseline.sha256"
    if registry_hash is not None:
        reg.write_text(registry_hash + "  image\n")
    clk = Clock()
    args = dict(containment=FakeNet(), baseline_image=str(img), registry=str(reg), hasher=lambda p: image_hash,
                ping=lambda ip: True, http=lambda ip: 200, clock=clk.now, sleep=clk.sleep)
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
    def __init__(self, ok):
        self.ok, self.calls = ok, 0

    def verify(self, ip):
        self.calls += 1
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
    assert v.calls == 1 and status == "verified"
    assert sorted(checks) == [("baseline", None), ("boot", 1)] and notes == []


def test_engine_with_failed_check_is_unverified_and_notifies(tmp_path):
    v = StubVerifier(False)
    out, status, checks, notes = heal_then_calm(tmp_path, v, "fail")
    assert status == "unverified"                               # calm windows alone are not enough
    assert ("boot", 0) in checks
    assert notes and notes[0][0] == "notify" and "boot" in notes[0][1]
