#!/usr/bin/env python3
"""twin_console.py - run one shell command inside the twin through FirmAE's serial console socket.

  sudo python3 experiments/member2/twin_console.py 'ls /etc'        # prints the output, exit 0
  sudo python3 experiments/member2/twin_console.py --probe          # exit 0 if a shell answers

FirmAE attaches the firmware's second serial port to the unix socket /tmp/qemu.<IID>.S1. If the
firmware runs a shell there, a command written to it is executed and its output comes back. Each
command is wrapped in unique start/end markers so only its own output is returned.
"""
import os
import socket
import sys
import time
import uuid

SOCK = "/tmp/qemu.%s.S1" % os.environ.get("IID", "1")


def run(cmd, timeout=10.0, sock_path=SOCK):
    tag = uuid.uuid4().hex[:8]
    start, end = "S%s" % tag, "E%s" % tag
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(sock_path)
    try:
        s.sendall(b"\n")                       # wake the console, drop anything pending
        time.sleep(0.3)
        try:
            while s.recv(65536):
                pass
        except socket.timeout:
            pass
        # markers are built by the shell (echo S$x) so the echoed command line never matches them
        line = "x=%s; echo S$x; %s; echo E$x\n" % (tag, cmd)
        s.sendall(line.encode())
        buf, t_end = b"", time.time() + timeout
        while time.time() < t_end:
            try:
                chunk = s.recv(65536)
                if chunk:
                    buf += chunk
                    text = buf.decode(errors="replace")
                    if end in text.split(start, 1)[-1] and start in text:
                        out = text.split(start, 1)[1].split(end, 1)[0]
                        return out.strip("\r\n")
            except socket.timeout:
                continue
        raise TimeoutError("no answer from the twin console within %.0f s" % timeout)
    finally:
        s.close()


def main():
    args = sys.argv[1:]
    if args == ["--probe"]:
        try:
            out = run("echo console-ok", timeout=8)
        except Exception as e:
            print("no shell on %s: %s" % (SOCK, e))
            sys.exit(1)
        print(out)
        sys.exit(0 if "console-ok" in out else 1)
    print(run(" ".join(args)))


if __name__ == "__main__":
    main()
