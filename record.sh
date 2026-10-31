#!/bin/bash
# record.sh — record RAW windows from all three monitors on the twin host.
#
#   ./record.sh                    record until Ctrl-C into data/raw/session_<time>.jsonl
#   ./record.sh 600                record for 600 seconds
#
# While it runs, label what you do from a second terminal:
#   python3 stream/label_run.py --manifest data/run_manifest.jsonl --label benign --seconds 120
#   python3 stream/label_run.py --manifest data/run_manifest.jsonl --label malware -- sudo nmap -T4 -p 1-1000 192.168.0.1
#   python3 stream/label_run.py --manifest data/run_manifest.jsonl --label healing --pad 150 -- ./twin.sh restart
#
# A restore takes the twin's network interface away, which ends the sniffer. Without a
# fixed duration the recorder therefore waits for the interface and carries on in a new
# session file, so a restore and the boot after it can be recorded too.
set -u
IFACE="${IFACE:-tap1_0.1}"
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
SYSCALL_LOG="${SYSCALL_LOG:-$FIRMAE_DIR/scratch/${IID:-1}/qemu.final.serial.log}"
cd "$(dirname "$0")"
HERE="$(pwd)"
mkdir -p data/raw
DUR="${1:-0}"
[ -f "$SYSCALL_LOG" ] || echo "[record] warning: $SYSCALL_LOG not found - syscall features will be zero"

sudo -v || exit 1
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
KEEPALIVE=$!
STOP=0
trap 'STOP=1' INT TERM
trap 'kill $KEEPALIVE 2>/dev/null' EXIT
iface_up() { ip link show "$IFACE" 2>/dev/null | grep -q '[<,]UP[,>]'; }

while [ "$STOP" = 0 ]; do
  if ! iface_up; then
    echo "[record] waiting for $IFACE (twin stopped or rebooting) - Ctrl-C to finish"
    until iface_up || [ "$STOP" = 1 ]; do sleep 2; done
    [ "$STOP" = 1 ] && break
    sleep 2
  fi
  OUT="data/raw/session_$(date -u +%Y%m%dT%H%M%S).jsonl"
  echo "[record] writing $OUT  (Ctrl-C to stop)"
  ( cd stream && sudo python3 run.py record --iface "$IFACE" --window 5 --syscall-log "$SYSCALL_LOG" \
       --duration "$DUR" --out "$HERE/$OUT" )
  [ "$DUR" != "0" ] && break
  [ "$STOP" = 1 ] && break
  sleep 3
done
echo "[record] finished. Raw sessions:"; ls -1 data/raw/*.jsonl 2>/dev/null | sed 's/^/  /'
