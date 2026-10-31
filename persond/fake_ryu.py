#!/usr/bin/env python3
"""fake_ryu.py - a tiny stand-in for Ryu's REST API (ofctl_rest), so containment.py can be
tested on a laptop. Keeps flow rules in memory. Like tests/fake_restore.py, never used on the twin.

  python persond/fake_ryu.py              # listens on http://127.0.0.1:8080
  python persond/fake_ryu.py 8099         # another port
  set FAKE_RYU_NO_METER=1                 # pretend the switch has no meter support
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DPID = 1
FLOWS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/stats/switches":
            return self._send(200, [DPID])
        if self.path == "/stats/flow/%d" % DPID:
            return self._send(200, {str(DPID): FLOWS})
        self._send(404, {"error": self.path})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/stats/flowentry/add":
            FLOWS.append({"cookie": body.get("cookie", 0), "priority": body.get("priority"),
                          "match": body.get("match", {}), "actions": body.get("actions", [])})
            return self._send(200, {})
        if self.path == "/stats/flowentry/delete":
            mask = body.get("cookie_mask", 0)
            FLOWS[:] = [f for f in FLOWS if not mask or (f["cookie"] & mask) != (body.get("cookie", 0) & mask)]
            return self._send(200, {})
        if self.path == "/stats/meterentry/add":
            if os.environ.get("FAKE_RYU_NO_METER"):
                return self._send(500, {"error": "meters not supported"})
            return self._send(200, {})
        self._send(404, {"error": self.path})


def start(port=8080):
    """Start in a background thread (for tests). Returns the server; call .shutdown() to stop."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print("fake Ryu on http://127.0.0.1:%d (Ctrl-C to stop)" % port)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
