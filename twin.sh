#!/bin/bash
# twin.sh — check on, restart or stop the emulated router.
#
#   ./twin.sh status     is the emulator running, is its console there, does it answer ping
#   ./twin.sh restart    restore to the clean baseline and reboot (runs restore.sh)
#   ./twin.sh watch      print the twin's state every 15 s until it stops (to time a crash)
#   ./twin.sh clean      remove tap interfaces left behind by a dead emulator
#   ./twin.sh diagnose   print everything needed to see why the twin is not answering
#   ./twin.sh stop       stop the emulator
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
IID="${IID:-1}"
IP="${IP:-192.168.0.1}"
cd "$(dirname "$0")"
case "${1:-status}" in
  status)
    PIDS=$(pgrep -f 'qemu-system-' | tr '\n' ' ')
    echo "emulator process : ${PIDS:-NOT RUNNING}"
    if sudo test -S "/tmp/qemu.$IID.S1"; then echo "device console   : /tmp/qemu.$IID.S1 present"; else echo "device console   : missing"; fi
    if ping -c 2 -W 1 "$IP" >/dev/null 2>&1; then echo "ping $IP : answers"; else echo "ping $IP : NO ANSWER"; fi
    [ -n "$PIDS" ] && echo "emulator uptime  : $(ps -o etime= -p ${PIDS%% *} | tr -d ' ')"
    ;;
  clean)
    # Remove tap interfaces left behind by an emulator that died without cleaning up.
    # FirmAE's start-up script aborts with "RTNETLINK answers: File exists" if they exist.
    if pgrep -f 'qemu-system-' >/dev/null; then echo "[twin] emulator is running - not touching its interfaces"; exit 1; fi
    for l in $(ip -o link | grep -o "tap${IID}_[0-9]*\.[0-9]*" | sort -u) $(ip -o link | grep -o "tap${IID}_[0-9]*" | sort -u); do
      sudo ip link delete "$l" 2>/dev/null && echo "[twin] removed stale interface $l"
    done
    exit 0 ;;
  watch)
    # Print the twin's state every 15 s until it stops answering, then say when it died.
    T0=$(date +%s)
    while true; do
      PID=$(pgrep -f 'qemu-system-' | head -1)
      UP=$([ -n "$PID" ] && ps -o etimes= -p "$PID" | tr -d ' ' || echo "-")
      if ping -c 1 -W 1 "$IP" >/dev/null 2>&1; then P=answers; else P="NO ANSWER"; fi
      if [ -n "$PID" ]; then E="pid $PID, up ${UP} s"; else E="NOT RUNNING"; fi
      echo "$(date +%T)  emulator: $E   ping: $P"
      [ -z "$PID" ] && { echo "[twin] emulator gone after watching $(( $(date +%s) - T0 )) s"; break; }
      sleep 15
    done ;;
  restart)
    # On the OVS bridge (network/twin_net.sh setup done): restore detached and re-attach.
    if sudo ovs-vsctl br-exists br-twin 2>/dev/null; then exec bash network/twin_net.sh heal; fi
    # restore.sh run directly: the way that is proven to boot the twin on this host.
    sudo pkill -f 'qemu-system-' 2>/dev/null; sleep 3
    bash ./twin.sh clean
    sudo rm -f /tmp/firmae_restore.log
    bash "$FIRMAE_DIR/restore.sh"; CODE=$?
    stty sane 2>/dev/null
    echo
    echo "[twin] The emulator is attached to THIS terminal. Leave this terminal alone"
    echo "[twin] (no Ctrl-C, do not close it) and work in a second terminal."
    exit $CODE ;;
  diagnose)
    echo "== status";            bash ./twin.sh status
    echo "== emulator processes"; pgrep -a -f 'qemu-system-|FirmAE/run.sh|scratch/[0-9]*/run.sh' | cut -c1-160
    echo "== interfaces";        ip -br addr 2>/dev/null | grep -E 'tap|br' || echo "(no tap interfaces)"
    echo "== boot log (last 15 lines of /tmp/firmae_restore.log)"; sudo tail -n 15 /tmp/firmae_restore.log 2>&1
    echo "== serial log";        sudo ls -la "$FIRMAE_DIR/scratch/$IID/qemu.final.serial.log" 2>&1
    sudo tail -c 3000 "$FIRMAE_DIR/scratch/$IID/qemu.final.serial.log" 2>/dev/null | strings | tail -n 12 | cut -c1-200
    echo "== syscall level in run script"; grep -o 'firmadyne.syscall=[0-9]*' "$FIRMAE_DIR/scratch/$IID/run.sh" 2>&1
    ;;
  stop)    sudo pkill -f 'qemu-system-' && echo "stopped" || echo "nothing to stop" ;;
  *) echo "usage: ./twin.sh status | restart | watch | diagnose | clean | stop"; exit 1 ;;
esac
