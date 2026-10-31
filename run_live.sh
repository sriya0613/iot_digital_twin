#!/bin/bash
# run_live.sh — the real-time closed loop, on Person 1's FirmAE/Mininet host.
#
#   ./run_live.sh --dry-run      # rehearsal: detect and log, never restore
#   ./run_live.sh                # full loop: detect -> restore.sh -> healed
#
# The fingerprint stream prints one record per 5-second window; live_detector.py
# scores each one and runs restore.sh when a window is malicious.
#
#   ./run_live.sh                         network-only model in models/
#   MODEL_DIR=models_v2 ./run_live.sh     three-monitor model (network + syscall + energy)
#
# Override with environment variables if your paths differ:
#   IFACE=tap1_0.1  RESTORE=/home/vboxuser/firmae/FirmAE/restore.sh  GRACE=30
#   BRIDGED=1   twin on the OVS bridge (network/twin_net.sh): sniff the mirror port
#               twin-mon and heal with network/heal_bridged.sh
set -u
if [ "${BRIDGED:-0}" = 1 ]; then IFACE="${IFACE:-twin-mon}"; else IFACE="${IFACE:-tap1_0.1}"; fi
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
RESTORE="${RESTORE:-$FIRMAE_DIR/restore.sh}"
GRACE="${GRACE:-30}"
MODEL_DIR="${MODEL_DIR:-models}"                      # models = network only, models_v2 = three monitors
# Scaler: prefer the one saved next to the model (train_detector_v3 copies it there), so
# live normalisation always matches how the model was trained. Override with SCALER=...
if [ -z "${SCALER:-}" ] && [ -f "${MODEL_DIR:-models}/scaler.json" ]; then
  SCALER="${MODEL_DIR:-models}/scaler.json"
else
  SCALER="${SCALER:-data/scaler_v2.json}"
fi
SYSCALL_LOG="${SYSCALL_LOG:-$FIRMAE_DIR/scratch/${IID:-1}/qemu.final.serial.log}"
cd "$(dirname "$0")"
HERE="$(pwd)"

[ -f "$MODEL_DIR/xgboost.json" ] || { echo "[run_live] no trained model in $MODEL_DIR - run train_detector.py"; exit 1; }
SCHEMA=$(python3 -c "import json;print(json.load(open('$MODEL_DIR/config.json')).get('schema_version','1.0.0'))")
if [ "$SCHEMA" = "2.0.0" ]; then
  [ -f "$SCALER" ] || { echo "[run_live] $SCALER not found - build the dataset first (stream/run.py build)"; exit 1; }
  [ -f "$SYSCALL_LOG" ] || echo "[run_live] warning: syscall log $SYSCALL_LOG not found - syscall features will be zero"
  echo "[run_live] model $MODEL_DIR: network + syscall + energy (schema 2.0.0)"
else
  echo "[run_live] model $MODEL_DIR: network only (schema 1.0.0)"
fi
[ -f "$RESTORE" ] || echo "[run_live] warning: $RESTORE not found (fine for --dry-run)"

# Ask for the sudo password once, then keep it fresh: sniffing needs root and
# restore.sh calls sudo itself several minutes into the run.
sudo -v || exit 1
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
KEEPALIVE=$!
trap 'kill $KEEPALIVE 2>/dev/null' EXIT

# restore.sh kills and reboots QEMU, which can take the tap interface away and
# end the sniffer. So the stream is restarted whenever it stops.
iface_up() { ip link show "$IFACE" 2>/dev/null | grep -q '[<,]UP[,>]'; }

stream() {
  STOP=0
  trap 'STOP=1' INT TERM
  # keep going only while nobody pressed Ctrl-C and the detector is still running
  alive() { [ "$STOP" = 0 ] && pgrep -f "live_detector.py" >/dev/null; }
  sleep 1
  while alive; do
    if ! iface_up; then
      echo "[run_live] waiting for $IFACE to come back (device is rebooting)..." >&2
      until iface_up || ! alive; do sleep 2; done
      alive || break
      sleep 2
      echo "[run_live] $IFACE is up - restarting the stream" >&2
    fi
    if [ "$SCHEMA" = "2.0.0" ]; then
      ( cd stream && sudo python3 run.py stream --iface "$IFACE" --window 5 --scaler "$HERE/$SCALER" \
            --syscall-log "$SYSCALL_LOG" --out - 2>&1 >&3 \
          | grep -v -e '^Traceback' -e '^  ' -e '^ValueError: Interface' >&2 ) 3>&1
    else
      ( cd stream_v1 && sudo python3 run.py stream --iface "$IFACE" --window 5 --scaler scaler.json --out - 2>&1 >&3 \
          | grep -v -e '^Traceback' -e '^  ' -e '^ValueError: Interface' >&2 ) 3>&1
    fi
    alive || break
    sleep 3
  done
  echo "[run_live] stopped." >&2
}

# SYSCALL_LIVE=7 : the device was recorded with the syscall level raised at run time
# (./syscall_level.sh live 7). A restore reboots it back to the boot level, so wait for
# the start-up scripts to finish and raise it again, inside the cool-down.
# The restore calls restore.sh directly: this is the path proven on the twin host.
# DETACH=1 uses heal.sh instead (emulator detached from this terminal). EXPERIMENTAL:
# on the twin host the device did not come up when started that way.
if [ "${BRIDGED:-0}" = 1 ]; then HEAL="bash $HERE/network/heal_bridged.sh"
elif [ "${DETACH:-0}" = "1" ]; then HEAL="bash $HERE/heal.sh"; else HEAL="bash $RESTORE"; fi
echo "[run_live] capture on $IFACE, heal with: $HEAL"
export RESTORE FIRMAE_DIR
POST=()
if [ -n "${SYSCALL_LIVE:-}" ]; then
  POST=(--post-restore-cmd "bash -c 'sleep ${SYSCALL_SETTLE:-45}; bash $HERE/syscall_level.sh live $SYSCALL_LIVE'")
  echo "[run_live] will re-apply syscall level $SYSCALL_LIVE after each restore"
fi

ALERTS="${ALERTS:-logs/alerts.jsonl}"      # alert feed for the policy engine (HANDOFF_to_personD.md)
echo "[run_live] alert feed: $ALERTS"
stream | python3 live_detector.py --model-dir "$MODEL_DIR" --restore-cmd "$HEAL" --grace "$GRACE" --alerts-out "$ALERTS" "${POST[@]}" "$@"
