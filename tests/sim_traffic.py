#!/usr/bin/env python3
"""tests/sim_traffic.py — benign traffic or a port scan against tests/sim_twin.py.

    python3 tests/sim_traffic.py benign --seconds 20     # a web request every ~0.7 s
    python3 tests/sim_traffic.py scan --ports 600        # connect scan of N ports from 8000
"""
import argparse
import socket
import time

ap = argparse.ArgumentParser()
ap.add_argument("kind", choices=["benign", "scan"])
ap.add_argument("--seconds", type=float, default=20)
ap.add_argument("--ports", type=int, default=600)
a = ap.parse_args()

if a.kind == "benign":
    end = time.time() + a.seconds
    while time.time() < end:
        try:
            c = socket.create_connection(("127.0.0.1", 8080), timeout=1)
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            while c.recv(4096):
                pass
            c.close()
        except OSError:
            pass
        time.sleep(0.7)
else:
    for port in range(8000, 8000 + a.ports):
        c = socket.socket()
        c.settimeout(0.05)
        try:
            c.connect(("127.0.0.1", port))
        except OSError:
            pass
        c.close()
