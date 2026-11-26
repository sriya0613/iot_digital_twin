#!/usr/bin/env python3
"""verify_heal.py - independent, multi-factor checks that a heal really restored the twin (EXP-7, C10).

The healing engine's own check is behavioural: the next 3 post-grace windows must score low. This module
adds checks that do not depend on the detector, each reported separately:

  baseline   the clean baseline image (image.baseline.raw) still has the SHA-256 registered when it was
             known to be clean. restore.sh copies this file over image.raw and boots it, so a changed
             baseline would make every heal restore a compromised image.
             NOT checked: the running image.raw itself - after restore.sh boots it the firmware writes to
             it, so its hash differs from the baseline even on a perfect heal. Checking it would need a
             hook inside restore.sh between copy and boot (see scripts/check_env.sh output).
  boot       the twin answers ping within BOOT_TIMEOUT (60 s)
  service    the web UI answers HTTP within SERVICE_TIMEOUT (90 s), with a status in ACCEPT_HTTP
             (default: any HTTP response; set the twin's real code once check_env.sh has recorded it)
  network    no containment rule of ours (cookies 0xD0000001 / 0xD0000002) is left on the switch
  client     optional: a command that must succeed, e.g. "sudo ip netns exec cli ping -c1 -W1 192.168.0.1"

Every check is read-only. Nothing here restarts, isolates or modifies the twin.

  python persond/verify_heal.py --register-baseline       # once, on a known-clean baseline
  python persond/verify_heal.py 192.168.0.1 --containment ryu --client-cmd "sudo ip netns exec cli ping -c1 -W1 192.168.0.1"
"""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from containment import COOKIE_ISOLATE, COOKIE_RATE  # noqa: E402

FIRMAE_DIR = os.environ.get("FIRMAE_DIR", "/home/vboxuser/firmae/FirmAE")
IID = os.environ.get("IID", "1")
BASELINE_IMAGE = os.path.join(FIRMAE_DIR, "scratch", IID, "image.baseline.raw")
REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "network", ".state", "baseline.sha256")
BOOT_TIMEOUT = 60
SERVICE_TIMEOUT = 90
POLL = 2.0
# Direct connections only: a system-wide HTTP proxy must never answer on the twin's behalf.
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ------------------------------------------------------------------ default probes (real, read-only)
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def ping_once(ip):
    return subprocess.call(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def http_status(ip, timeout=3):
    """HTTP status code of GET http://ip/, or None if nothing answered."""
    try:
        with _DIRECT.open(urllib.request.Request("http://%s/" % ip, method="GET"), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:      # 401/403/404 are still the twin answering
        return e.code
    except Exception:
        return None


def run_ok(cmd):
    try:
        return subprocess.call(shlex.split(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15) == 0
    except Exception:
        return False


# ------------------------------------------------------------------ verifier
class HealVerifier:
    def __init__(self, containment=None, baseline_image=BASELINE_IMAGE, registry=REGISTRY,
                 boot_timeout=BOOT_TIMEOUT, service_timeout=SERVICE_TIMEOUT, accept_http=None, client_cmd=None,
                 ping=ping_once, http=http_status, hasher=sha256_file, run=run_ok,
                 clock=time.monotonic, sleep=time.sleep, poll=POLL):
        self.net = containment
        self.baseline_image, self.registry = baseline_image, registry
        self.boot_timeout, self.service_timeout = boot_timeout, service_timeout
        self.accept_http = set(accept_http) if accept_http else None      # None = any HTTP answer
        self.client_cmd = client_cmd
        self.ping, self.http, self.hasher, self.run_cmd = ping, http, hasher, run
        self.clock, self.sleep, self.poll = clock, sleep, poll

    # each check returns {"factor", "ok", "detail", "seconds"}; ok is True / False / None (= not checked)
    def _timed(self, factor, fn):
        t0 = self.clock()
        try:
            ok, detail = fn()
        except Exception as e:                       # a broken probe is a failed check, never a pass
            ok, detail = False, "check error: %s" % e
        return {"factor": factor, "ok": ok, "detail": detail, "seconds": round(self.clock() - t0, 3)}

    def check_baseline(self):
        def fn():
            if not os.path.exists(self.registry):
                return None, "no registered hash (run --register-baseline on a known-clean baseline)"
            want = open(self.registry).read().split()[0]
            if not os.path.exists(self.baseline_image):
                return False, "baseline image missing: %s" % self.baseline_image
            got = self.hasher(self.baseline_image)
            return got == want, "sha256 %s %s registered %s" % (got[:16], "==" if got == want else "!=", want[:16])
        return self._timed("baseline", fn)

    def _wait(self, probe, timeout):
        end = self.clock() + timeout
        while True:
            r = probe()
            if r:
                return r
            if self.clock() >= end:
                return None
            self.sleep(self.poll)

    def check_boot(self, ip):
        def fn():
            ok = self._wait(lambda: self.ping(ip), self.boot_timeout)
            return bool(ok), "answers ping" if ok else "no ping answer within %d s" % self.boot_timeout
        return self._timed("boot", fn)

    def check_service(self, ip):
        def fn():
            def probe():
                code = self.http(ip)
                if code is None:
                    return None
                return code if (self.accept_http is None or code in self.accept_http) else None
            code = self._wait(probe, self.service_timeout)
            if code:
                return True, "HTTP %d" % code
            last = self.http(ip)
            return False, ("no HTTP answer within %d s" % self.service_timeout if last is None
                           else "HTTP %s not in accepted %s" % (last, sorted(self.accept_http)))
        return self._timed("service", fn)

    def check_network(self):
        def fn():
            if self.net is None or getattr(self.net, "mode", "print") != "ryu":
                return None, "containment not in ryu mode - switch not checked"
            left = [f for f in self.net._flows() if int(f.get("cookie", 0)) in (COOKIE_ISOLATE, COOKIE_RATE)]
            return not left, "no containment rules left" if not left else "%d containment rule(s) still installed" % len(left)
        return self._timed("network", fn)

    def check_client(self):
        def fn():
            if not self.client_cmd:
                return None, "no client command configured"
            ok = self.run_cmd(self.client_cmd)
            return ok, ("ok: " if ok else "failed: ") + self.client_cmd
        return self._timed("client", fn)

    # Checks that work while the device is still isolated (only the twin host can reach it), and the
    # ones that need the isolation lifted (our rules gone, a normal client reaches the device).
    WHILE_ISOLATED = ("baseline", "boot", "service")
    AFTER_RELEASE = ("network", "client")

    def verify(self, ip, factors=None):
        """Run the checks (all, or only those named in factors). Returns {"ok": bool, "failed": [...],
        "skipped": [...], "checks": [...]}. ok is True only if no check FAILED; unchecked factors (None)
        are listed, not counted as passes."""
        run = {"baseline": self.check_baseline, "boot": lambda: self.check_boot(ip),
               "service": lambda: self.check_service(ip), "network": self.check_network, "client": self.check_client}
        names = factors or ("baseline", "boot", "service", "network", "client")
        checks = [run[n]() for n in names]
        failed = [c["factor"] for c in checks if c["ok"] is False]
        skipped = [c["factor"] for c in checks if c["ok"] is None]
        return {"ok": not failed, "failed": failed, "skipped": skipped, "checks": checks}


def register_baseline(image=BASELINE_IMAGE, registry=REGISTRY, hasher=sha256_file):
    h = hasher(image)
    os.makedirs(os.path.dirname(registry), exist_ok=True)
    with open(registry, "w") as f:
        f.write("%s  %s  registered %s\n" % (h, image, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device", nargs="?", default="192.168.0.1")
    ap.add_argument("--register-baseline", action="store_true")
    ap.add_argument("--containment", default="print", choices=["print", "ryu"])
    ap.add_argument("--ryu-url", default="http://127.0.0.1:8080")
    ap.add_argument("--dpid", type=int)
    ap.add_argument("--accept-http", help="comma-separated status codes, e.g. 200,302 (default: any)")
    ap.add_argument("--client-cmd")
    a = ap.parse_args()
    if a.register_baseline:
        print("registered", register_baseline(), "->", REGISTRY)
        return
    from containment import Containment
    v = HealVerifier(Containment(a.containment, a.ryu_url, a.dpid),
                     accept_http=[int(x) for x in a.accept_http.split(",")] if a.accept_http else None,
                     client_cmd=a.client_cmd)
    r = v.verify(a.device)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
