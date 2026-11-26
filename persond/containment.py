#!/usr/bin/env python3
"""containment.py - SDN containment through the Ryu controller (diagram: SDN Controller ->
Traffic Containment -> Rule Verification).

Two modes:
  print  (default, laptop)  only prints what it would do; always "succeeds"
  ryu    (twin host)        talks to Ryu's REST API (ryu.app.ofctl_rest, http://127.0.0.1:8080),
                            which Person A runs:  ryu-manager ryu.app.ofctl_rest network/ryu_base.py

What it does in ryu mode
  isolate(ip)     drop rules for the device's MAC in both directions (priority 200), plus narrow allow
                  rules (priority 300) between the device and the twin host 192.168.0.2, so restore.sh /
                  twin_net.sh heal can still check that the device answers. The allow rules match MAC
                  and IP on both ends, and the host side also its switch port (twin-host, which is never
                  recreated). Anti-spoof drops (priority 400) stop any other port from sending with the
                  host's or the device's MAC, so a quarantined neighbour cannot pose as either (IMP-01).
  release(ip)     delete those rules (by cookie)
  rate_limit(ip)  an OpenFlow meter (default 1000 kbit/s) on the device's traffic (priority 150)
  unlimit(ip)     delete the meter rule
  After every add, the rules are READ BACK from the switch (GET /stats/flow/<dpid>) and each expected
  rule is checked field by field (priority, match, actions), not just counted (IMP-04). The result (ok, verified, seconds) is returned and saved in threat.db.

Rules match the device's MAC address, not a switch port, because twin_net.sh heal recreates the
twin's tap interface on every heal (a port-based rule would be lost).

The anti-spoof and field-by-field verification (IMP-01, IMP-04) are unit-tested against a fake
switch (tests/test_containment.py) but NOT YET ON THE TWIN. Check with Person A's network/containment_test.sh before relying on it:
  - field names of the match (eth_src / eth_dst / ipv4_src ...) on her Ryu 4.34
  - whether her OVS supports meters (rate-limit); if not, rate_limit() reports ok=False
  - the switch datapath id (from `bash network/twin_net.sh status --json`); if not given, the first
    switch Ryu knows is used

  python persond/containment.py --mode ryu isolate 192.168.0.1     # try it by hand on the twin host
  python persond/containment.py --mode ryu release 192.168.0.1
  python persond/containment.py --mode ryu show
"""
import argparse
import json
import time
import urllib.error
import urllib.request

DEVICE_MACS = {"192.168.0.1": "00:de:fa:1a:01:00"}   # from person_a_network.md
TWIN_HOST_IP = "192.168.0.2"                           # restore checks come from here: keep them allowed
COOKIE_ISOLATE = 0xD0000001                            # our rules carry these cookies, so we only ever
COOKIE_RATE = 0xD0000002                               # delete our own rules
HOST_PORT_NAME = "twin-host"                           # OVS internal port of the twin host (stable)
TWIN_PORT_PREFIX = "tap"                               # FirmAE's tap for the twin (recreated on heal)
METER_ID = 7
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # Ryu is local: never use a proxy
RATE_KBPS = 1000


# Ryu's ofctl_rest (OpenFlow 1.3) may report match fields under their OpenFlow 1.0 names and
# actions as strings ("OUTPUT:NORMAL", "METER:7"). Both sides are brought to one form to compare.
_ALIASES = {"dl_src": "eth_src", "dl_dst": "eth_dst", "dl_type": "eth_type",
            "nw_src": "ipv4_src", "nw_dst": "ipv4_dst", "nw_proto": "ip_proto"}


def _norm_val(v):
    if isinstance(v, str):
        t = v.strip().lower()
        try:
            return int(t, 0) if t.startswith("0x") or t.isdigit() else t
        except ValueError:
            return t
    return v


def _norm_match(m):
    return tuple(sorted((_ALIASES.get(k, k), _norm_val(v)) for k, v in (m or {}).items()))


def _norm_actions(flow):
    out = []
    for a in list(flow.get("actions") or []) + list(flow.get("instructions") or []):
        if isinstance(a, dict):
            t = str(a.get("type", "")).upper()
            arg = a.get("port", a.get("meter_id", ""))
            out.append("%s:%s" % (t, str(arg).upper()) if arg != "" else t)
        else:
            out.append(str(a).upper().replace(" ", ""))
    return tuple(sorted(out))


class Containment:
    def __init__(self, mode="print", ryu_url="http://127.0.0.1:8080", dpid=None, timeout=3):
        assert mode in ("print", "ryu"), mode
        self.mode, self.url, self.dpid, self.timeout = mode, ryu_url.rstrip("/"), dpid, timeout

    # ---- REST helpers ------------------------------------------------------------------------
    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with _OPENER.open(req, timeout=self.timeout) as r:
            text = r.read().decode() or "null"
            return json.loads(text) if text.strip()[:1] in "{[" else text

    def _dpid(self):
        if self.dpid is None:
            switches = self._call("GET", "/stats/switches")
            if not switches:
                raise RuntimeError("Ryu knows no switch")
            self.dpid = switches[0]
        return int(self.dpid)

    def _flows(self):
        dp = self._dpid()
        out = self._call("GET", "/stats/flow/%d" % dp)
        return out.get(str(dp), [])

    def _has_cookie(self, cookie, n):
        return sum(1 for f in self._flows() if int(f.get("cookie", 0)) == cookie) >= n

    def _ports(self):
        """{name: (port_no, mac)} for every port on the switch."""
        dp = self._dpid()
        out = self._call("GET", "/stats/portdesc/%d" % dp)
        ports = {}
        for p in out.get(str(dp), []):
            ports[p.get("name")] = (p.get("port_no"), (p.get("hw_addr") or "").lower())
        return ports

    def _verify(self, cookie, expected):
        """Every expected (priority, match, actions) rule is on the switch under our cookie."""
        have = [(int(f.get("priority", -1)), _norm_match(f.get("match", {})), _norm_actions(f))
                for f in self._flows() if int(f.get("cookie", 0)) == cookie]
        missing = [e for e in expected
                   if (e[0], _norm_match(e[1]), _norm_actions({"actions": e[2]})) not in have]
        if missing:
            print("    -> rule verification: %d of %d rules missing, e.g. %s" % (len(missing), len(expected), missing[0]))
        return not missing

    def _add(self, priority, match, actions, cookie):
        body = {"dpid": self._dpid(), "cookie": cookie, "priority": priority, "match": match, "actions": actions}
        self._call("POST", "/stats/flowentry/add", body)

    def _delete_cookie(self, cookie):
        self._call("POST", "/stats/flowentry/delete",
                   {"dpid": self._dpid(), "cookie": cookie, "cookie_mask": 0xFFFFFFFF})

    def _match_sets(self, ip):
        """Two matches that cover all traffic from and to the device."""
        mac = DEVICE_MACS.get(ip)
        if mac:
            return [{"eth_src": mac}, {"eth_dst": mac}]
        return [{"eth_type": 0x0800, "ipv4_src": ip}, {"eth_type": 0x0800, "ipv4_dst": ip}]

    def _run(self, what, ip, fn):
        """Run fn in ryu mode, time it, never raise. Returns dict(ok, verified, seconds, detail)."""
        if self.mode == "print":
            print("    -> would %s %s" % (what, ip))
            return {"ok": True, "verified": None, "seconds": 0.0, "detail": "print mode"}
        t0 = time.time()
        try:
            verified = fn()
            res = {"ok": True, "verified": verified, "detail": "dpid %s" % self.dpid}
        except (urllib.error.URLError, OSError, RuntimeError, ValueError) as e:
            res = {"ok": False, "verified": False, "detail": "%s: %s" % (type(e).__name__, e)}
        res["seconds"] = round(time.time() - t0, 3)
        print("    -> %s %s via Ryu: ok=%s verified=%s (%.3f s) %s" % (
            what.upper(), ip, res["ok"], res["verified"], res["seconds"], "" if res["ok"] else res["detail"]))
        return res

    # ---- the four actions ----------------------------------------------------------------------
    def isolate_rules(self, ip):
        """The (priority, match, actions) rules isolate() installs. Needs the switch's port list."""
        normal = [{"type": "OUTPUT", "port": "NORMAL"}]
        dev_mac = DEVICE_MACS.get(ip)
        ports = self._ports()
        if HOST_PORT_NAME not in ports:
            raise RuntimeError("no %s port on the switch" % HOST_PORT_NAME)
        host_port, host_mac = ports[HOST_PORT_NAME]
        rules = [(200, m, []) for m in self._match_sets(ip)]                     # [] actions = drop
        if not dev_mac:              # unknown MAC: IP drops only, no allow rules we cannot pin down
            return rules
        # narrow allow rules, so restore checks from the twin host keep working
        rules += [
            (300, {"in_port": host_port, "eth_src": host_mac, "eth_dst": dev_mac,
                   "eth_type": 0x0800, "ipv4_src": TWIN_HOST_IP, "ipv4_dst": ip}, normal),
            (300, {"eth_src": dev_mac, "eth_dst": host_mac,
                   "eth_type": 0x0800, "ipv4_src": ip, "ipv4_dst": TWIN_HOST_IP}, normal),
            (300, {"in_port": host_port, "eth_src": host_mac, "eth_type": 0x0806,
                   "arp_spa": TWIN_HOST_IP, "arp_tpa": ip}, normal),
            (300, {"eth_src": dev_mac, "eth_type": 0x0806, "arp_spa": ip, "arp_tpa": TWIN_HOST_IP}, normal),
            # any other ARP about the device (e.g. a broadcast who-has from the attacker) is dropped
            (250, {"eth_type": 0x0806, "arp_tpa": ip}, []),
            (250, {"eth_type": 0x0806, "arp_spa": ip}, []),
        ]
        # anti-spoof: only twin-host may send with the host MAC, only the twin's tap with the device MAC
        for name, (port_no, _mac) in sorted(ports.items(), key=lambda kv: str(kv[0])):
            if port_no in ("LOCAL", 0xFFFFFFFE) or name == HOST_PORT_NAME:
                continue
            rules.append((400, {"in_port": port_no, "eth_src": host_mac}, []))
            if not str(name).startswith(TWIN_PORT_PREFIX):
                rules.append((400, {"in_port": port_no, "eth_src": dev_mac}, []))
        rules.append((400, {"in_port": host_port, "eth_src": dev_mac}, []))
        return rules

    def isolate(self, ip):
        def fn():
            rules = self.isolate_rules(ip)
            for prio, match, actions in rules:
                self._add(prio, match, actions, COOKIE_ISOLATE)
            return self._verify(COOKIE_ISOLATE, rules)                          # rule verification
        return self._run("isolate", ip, fn)

    def release(self, ip):
        def fn():
            self._delete_cookie(COOKIE_ISOLATE)
            return not self._has_cookie(COOKIE_ISOLATE, 1)
        return self._run("release", ip, fn)

    def rate_limit(self, ip):
        def fn():
            self._call("POST", "/stats/meterentry/add",
                       {"dpid": self._dpid(), "meter_id": METER_ID, "flags": "KBPS",
                        "bands": [{"type": "DROP", "rate": RATE_KBPS}]})
            rules = [(150, m, [{"type": "METER", "meter_id": METER_ID}, {"type": "OUTPUT", "port": "NORMAL"}])
                     for m in self._match_sets(ip)]
            for prio, match, actions in rules:
                self._add(prio, match, actions, COOKIE_RATE)
            return self._verify(COOKIE_RATE, rules)
        return self._run("rate-limit", ip, fn)

    def unlimit(self, ip):
        def fn():
            self._delete_cookie(COOKIE_RATE)
            return not self._has_cookie(COOKIE_RATE, 1)
        return self._run("remove rate-limit", ip, fn)


def main():
    ap = argparse.ArgumentParser(description="Try containment by hand.")
    ap.add_argument("--mode", default="print", choices=["print", "ryu"])
    ap.add_argument("--ryu-url", default="http://127.0.0.1:8080")
    ap.add_argument("--dpid", type=int)
    ap.add_argument("action", choices=["isolate", "release", "rate_limit", "unlimit", "show"])
    ap.add_argument("ip", nargs="?", default="192.168.0.1")
    a = ap.parse_args()
    c = Containment(a.mode, a.ryu_url, a.dpid)
    if a.action == "show":
        if a.mode == "print":
            print("show needs --mode ryu")
            return
        for f in c._flows():
            print(f.get("priority"), hex(int(f.get("cookie", 0))), f.get("match"), f.get("actions"))
        return
    print(getattr(c, a.action)(a.ip))


if __name__ == "__main__":
    main()
