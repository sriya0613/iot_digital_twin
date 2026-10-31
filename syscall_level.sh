#!/bin/bash
# syscall_level.sh — show or change how much the twin's kernel logs about system calls.
#
# FirmAE boots the firmware on an instrumented kernel that prints a line to the serial
# log (scratch/<id>/qemu.final.serial.log) for hooked kernel calls. A bit mask on the
# kernel command line chooses which ones:
#     1  network   socket, setsockopt, bind, accept                 (FirmAE default)
#     2  system    execve, mount, ioctl, reboot
#     4  fs write  unlink, mknod
#     8  fs read   open, close                                      (very chatty)
#    16  process   fork, exit, signals, executable mmap
#
#   ./syscall_level.sh            show the current level and what the log contains
#   ./syscall_level.sh 23         set network + system + fs write + process (recommended)
#   ./syscall_level.sh 1          back to the FirmAE default
#   ./syscall_level.sh live 7     change the RUNNING twin, no reboot (see below)
#
# A new level takes effect the next time the twin boots (restore.sh, or start it again).
# The original run script is kept as run.sh.bak the first time you change it.
set -u
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
IID="${IID:-1}"
RUN="$FIRMAE_DIR/scratch/$IID/run.sh"
LOG="$FIRMAE_DIR/scratch/$IID/qemu.final.serial.log"
[ -f "$RUN" ] || { echo "not found: $RUN  (set FIRMAE_DIR / IID)"; exit 1; }

show() {
  echo "run script : $RUN"
  echo "level now  : $(grep -o 'user_debug=0 firmadyne.syscall=[0-9]*' "$RUN" | grep -o '[0-9]*$' | head -1)"
  if [ -f "$LOG" ]; then
    echo "serial log : $LOG ($(sudo cat "$LOG" | wc -l) lines, $(sudo grep -a -c 'firmadyne: ' "$LOG") kernel-hook lines)"
    echo "calls seen :"
    sudo grep -a -o 'firmadyne: [A-Za-z_]*\[PID' "$LOG" | sed 's/firmadyne: //; s/\[PID//' | sort | uniq -c | sort -rn | head -20
  else
    echo "serial log : $LOG not there yet (boot the twin once)"
  fi
}

# ---- live mode: change the level of the RUNNING twin, no reboot -----------------
# The kernel reads the level on every hooked call and exposes it as
# /sys/module/firmadyne/parameters/syscall inside the device. FirmAE attaches a
# root shell to the device's second serial port (/tmp/qemu.<id>.S1), so the level
# can be changed after the device has finished booting. Use this when a high
# boot-time level stalls the boot (thousands of start-up processes get logged).
#   ./syscall_level.sh live        show the running level
#   ./syscall_level.sh live 7      set it now; lasts until the twin reboots
live() {
  SOCK="/tmp/qemu.$IID.S1"
  sudo test -S "$SOCK" || { echo "no console socket $SOCK - is the twin running?"; return 1; }
  sudo python3 - "$SOCK" "${1:-}" <<'PYEOF'
import socket, sys, time, re
sock_path, level = sys.argv[1], sys.argv[2]
P = "/sys/module/firmadyne/parameters/syscall"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(sock_path)
def run(cmd, wait=1.0):
    s.sendall(("\n" + cmd + "\n").encode())
    time.sleep(wait)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    return out.decode(errors="replace")
if level:
    run("echo %s > %s" % (level, P), 0.5)
out = run("echo LEVEL=$(cat %s)=END" % P)
m = re.findall(r"LEVEL=(\d+)=END", out)
if not m:
    print("no answer from the device console (is it still booting?)"); sys.exit(1)
print("running level: %s%s" % (m[-1], "" if not level else ("  (set)" if m[-1] == level else "  (asked for %s - NOT applied)" % level)))
sys.exit(0 if (not level or m[-1] == level) else 1)
PYEOF
}
if [ "${1:-}" = "live" ]; then
  if [ -n "${2:-}" ]; then case "$2" in *[!0-9]*) echo "level must be a number 0-31"; exit 1;; esac; fi
  live "${2:-}"; exit $?
fi

if [ $# -eq 0 ]; then show; exit 0; fi
case "$1" in ''|*[!0-9]*) echo "level must be a number 0-31"; exit 1;; esac
grep -q 'user_debug=0 firmadyne.syscall=[0-9]*' "$RUN" || {
  echo "this run.sh has no 'user_debug=0 firmadyne.syscall=N' setting - not changing anything"; exit 1; }
[ -f "$RUN.bak" ] || sudo cp -p "$RUN" "$RUN.bak"
sudo sed -i "s/\(user_debug=0 firmadyne.syscall=\)[0-9]*/\1$1/" "$RUN"
echo "set to $1 - reboot the twin for it to take effect (e.g. bash $FIRMAE_DIR/restore.sh)"
show
