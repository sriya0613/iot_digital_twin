#!/usr/bin/env python3
"""tests/sim_twin.py — a stand-in for the emulated router, for testing the three
monitors on one Linux machine without FirmAE.

    python3 tests/sim_twin.py qemu-system-sim --log /tmp/sim_serial.log

  * listens on 127.0.0.1 ports 8080, 8443 and 2323 (the "device services")
  * writes Firmadyne-style kernel lines to --log for what it does
    (inet_accept / sys_socket / do_sys_open ...), like the QEMU serial log
  * burns a little CPU per connection, so the energy monitor sees activity
The word "qemu-system" in its command line is what the energy monitor looks for.
"""
import argparse
import os
import socket
import threading
import time

ap = argparse.ArgumentParser()
ap.add_argument("name", nargs="?", default="qemu-system-sim")
ap.add_argument("--log", default="/tmp/sim_serial.log")
ap.add_argument("--ports", default="8080,8443,2323")
a = ap.parse_args()

lock = threading.Lock()
t_boot = time.time()
logf = open(a.log, "w")


def klog(hook, pid, comm, rest=""):
    with lock:
        logf.write("[%12.6f] firmadyne: %s[PID: %d (%s)]:%s\n" % (time.time() - t_boot, hook, pid, comm, rest))
        logf.flush()


def burn(ms):
    end = time.time() + ms / 1000.0
    x = 0
    while time.time() < end:
        x += 1


def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    klog("sys_socket", 1289, "httpd", " family:2, type:1, protocol:0")
    klog("inet_bind", 1289, "httpd", " proto:SOCK_STREAM, port:%d" % port)
    while True:
        c, _ = s.accept()
        klog("inet_accept", 1289, "httpd")
        try:
            c.settimeout(0.2)
            data = c.recv(1024)
            if data:                                   # a real request, not just a port probe
                klog("do_sys_open", 1289, "httpd", " file:/htdocs/web/index.html")
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2000\r\n\r\n" + b"x" * 2000)
                klog("close", 1289, "httpd", " fd:5")
        except OSError:
            pass
        burn(8)
        c.close()


for p in a.ports.split(","):
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()

# background housekeeping the device does on its own
while True:
    time.sleep(2.0)
    klog("sys_socket", 412, "udhcpd", " family:2, type:2, protocol:17")
    klog("sys_setsockopt", 412, "udhcpd", " fd:4, level:1, optname:6")
    with open(os.devnull, "w") as f:
        f.write("x")
