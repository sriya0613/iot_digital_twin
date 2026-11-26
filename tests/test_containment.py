"""Tests for persond/containment.py against a fake Ryu switch (no VM needed).

IMP-01: while quarantined, nobody but the real twin host can reach the device, even by spoofing the
        host's MAC/IP or the device's MAC, and ARP is only allowed for the host and the device.
IMP-04: rule verification checks each rule's priority, match and actions, not a count of cookies.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "persond"))
from containment import COOKIE_ISOLATE, COOKIE_RATE, Containment, _ALIASES  # noqa: E402

DEV_IP, DEV_MAC = "192.168.0.1", "00:de:fa:1a:01:00"
HOST_IP, HOST_MAC = "192.168.0.2", "aa:bb:cc:00:00:02"
ATK_MAC, CLI_MAC = "02:00:00:00:00:10", "02:00:00:00:00:20"
PORTS = [  # as /stats/portdesc reports them
    {"port_no": 1, "name": "tap1_0", "hw_addr": "fe:00:00:00:00:01"},
    {"port_no": 2, "name": "twin-host", "hw_addr": HOST_MAC},
    {"port_no": 3, "name": "twin-mon", "hw_addr": "fe:00:00:00:00:03"},
    {"port_no": 4, "name": "v-atk", "hw_addr": "fe:00:00:00:00:04"},
    {"port_no": 5, "name": "v-cli", "hw_addr": "fe:00:00:00:00:05"},
    {"port_no": "LOCAL", "name": "br-twin", "hw_addr": "fe:00:00:00:00:ff"},
]
PORT = {"tap": 1, "host": 2, "atk": 4, "cli": 5}


class FakeSwitch:
    """Stores flows like OVS, reports them the way Ryu ofctl_rest (OF1.3) does."""

    def __init__(self, ryu_style=True, drop_some=False):
        self.flows, self.ryu_style, self.drop_some = [], ryu_style, drop_some

    def call(self, method, path, body=None):
        if path == "/stats/switches":
            return [1]
        if path.startswith("/stats/portdesc/"):
            return {"1": PORTS}
        if path.startswith("/stats/flow/"):
            return {"1": [self._report(f) for f in self.flows]}
        if path == "/stats/flowentry/add":
            if self.drop_some and len(self.flows) % 3 == 2:
                self.flows.append(dict(body, actions=[{"type": "OUTPUT", "port": "NORMAL"}]))  # wrong rule
            else:
                self.flows.append(body)
            return ""
        if path == "/stats/flowentry/delete":
            self.flows = [f for f in self.flows if f["cookie"] != body["cookie"]]
            return ""
        if path == "/stats/meterentry/add":
            return ""
        raise AssertionError(path)

    def _report(self, f):
        if not self.ryu_style:
            return f
        back = {v: k for k, v in _ALIASES.items()}
        acts = []
        for a in f["actions"]:
            acts.append("METER:%d" % a["meter_id"] if a["type"] == "METER" else "%s:%s" % (a["type"], a["port"]))
        return {"priority": f["priority"], "cookie": f["cookie"], "actions": acts,
                "match": {back.get(k, k): v for k, v in f["match"].items()}}

    # ---- packet walk: highest-priority matching rule wins; no rule = NORMAL forwarding
    def forwards(self, pkt):
        hits = [f for f in self.flows if all(pkt.get(k) == v for k, v in f["match"].items())]
        if not hits:
            return True
        return bool(max(hits, key=lambda f: f["priority"])["actions"])


def make(**kw):
    sw = FakeSwitch(**kw)
    c = Containment("ryu", dpid=1)
    c._call = sw.call
    return c, sw


def ip(in_port, src_mac, dst_mac, src_ip, dst_ip):
    return {"in_port": in_port, "eth_src": src_mac, "eth_dst": dst_mac, "eth_type": 0x0800,
            "ipv4_src": src_ip, "ipv4_dst": dst_ip}


def arp(in_port, src_mac, spa, tpa):
    return {"in_port": in_port, "eth_src": src_mac, "eth_dst": "ff:ff:ff:ff:ff:ff", "eth_type": 0x0806,
            "arp_spa": spa, "arp_tpa": tpa}


def test_isolate_verified_and_released():
    c, sw = make()
    r = c.isolate(DEV_IP)
    assert r["ok"] and r["verified"] is True
    assert c.release(DEV_IP)["verified"] is True
    assert sw.flows == []


def test_real_host_still_reaches_device():
    c, sw = make()
    c.isolate(DEV_IP)
    assert sw.forwards(ip(PORT["host"], HOST_MAC, DEV_MAC, HOST_IP, DEV_IP))
    assert sw.forwards(ip(PORT["tap"], DEV_MAC, HOST_MAC, DEV_IP, HOST_IP))
    assert sw.forwards(arp(PORT["host"], HOST_MAC, HOST_IP, DEV_IP))
    assert sw.forwards(arp(PORT["tap"], DEV_MAC, DEV_IP, HOST_IP))


def test_attacker_cut_off():
    c, sw = make()
    c.isolate(DEV_IP)
    assert not sw.forwards(ip(PORT["atk"], ATK_MAC, DEV_MAC, "192.168.0.10", DEV_IP))
    assert not sw.forwards(ip(PORT["tap"], DEV_MAC, ATK_MAC, DEV_IP, "192.168.0.10"))
    assert not sw.forwards(ip(PORT["cli"], CLI_MAC, DEV_MAC, "192.168.0.20", DEV_IP))


def test_spoofed_host_ip_blocked():          # old code: allowed (matched IPs only)
    c, sw = make()
    c.isolate(DEV_IP)
    assert not sw.forwards(ip(PORT["atk"], ATK_MAC, DEV_MAC, HOST_IP, DEV_IP))


def test_spoofed_host_mac_and_ip_blocked():
    c, sw = make()
    c.isolate(DEV_IP)
    assert not sw.forwards(ip(PORT["atk"], HOST_MAC, DEV_MAC, HOST_IP, DEV_IP))


def test_spoofed_device_mac_blocked():
    c, sw = make()
    c.isolate(DEV_IP)
    assert not sw.forwards(ip(PORT["atk"], DEV_MAC, HOST_MAC, DEV_IP, HOST_IP))


def test_attacker_arp_blocked():             # old code: all ARP allowed
    c, sw = make()
    c.isolate(DEV_IP)
    assert not sw.forwards(arp(PORT["atk"], ATK_MAC, "192.168.0.10", DEV_IP))   # who-has twin
    assert not sw.forwards(arp(PORT["atk"], ATK_MAC, HOST_IP, DEV_IP))          # spoofed sender IP
    assert not sw.forwards(arp(PORT["atk"], HOST_MAC, HOST_IP, DEV_IP))         # spoofed MAC + IP
    assert not sw.forwards(arp(PORT["tap"], DEV_MAC, DEV_IP, "192.168.0.10"))   # twin answers attacker
    assert sw.forwards(arp(PORT["atk"], ATK_MAC, "192.168.0.10", "192.168.0.20"))  # unrelated ARP untouched


def test_verification_catches_wrong_rule():  # old code: 5 cookie flows = verified
    c, sw = make(drop_some=True)
    assert c.isolate(DEV_IP)["verified"] is False


def test_verification_catches_missing_rule():
    c, sw = make()
    real = sw.call

    def lossy(method, path, body=None):
        if path == "/stats/flowentry/add" and body["priority"] == 400:
            return ""                         # anti-spoof rules silently not installed
        return real(method, path, body)
    c._call = lossy
    assert c.isolate(DEV_IP)["verified"] is False


def test_verification_with_plain_field_names():
    c, sw = make(ryu_style=False)
    assert c.isolate(DEV_IP)["verified"] is True


def test_rate_limit_verified():
    c, sw = make()
    assert c.rate_limit(DEV_IP)["verified"] is True
    assert all(f["cookie"] == COOKIE_RATE for f in sw.flows)
    assert c.unlimit(DEV_IP)["verified"] is True


def test_missing_host_port_fails_safe():
    c, sw = make()
    real = sw.call
    c._call = lambda m, p, b=None: {"1": [x for x in PORTS if x["name"] != "twin-host"]} \
        if p.startswith("/stats/portdesc/") else real(m, p, b)
    r = c.isolate(DEV_IP)
    assert r["ok"] is False and r["verified"] is False


def test_only_our_cookie():
    c, sw = make()
    c.isolate(DEV_IP)
    assert {f["cookie"] for f in sw.flows} == {COOKIE_ISOLATE}
