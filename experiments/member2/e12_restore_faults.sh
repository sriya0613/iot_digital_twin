#!/bin/bash
# experiments/member2/e12_restore_faults.sh — E12 / SYS-08: a restore that goes wrong must leave the twin
# isolated and held for a human, never released.
#
#   sudo bash experiments/member2/e12_restore_faults.sh [TRIALS] [FAULTS]
#        TRIALS per fault (default 5), FAULTS = "corrupt slow hung" (default: all three)   ~4-6 min per trial
#
# The engine (run_pipeline.py, containment ryu) gets one synthetic high-risk alert; its restore command is
# twin_net.sh heal with ONE fault injected (Sriya's restore.sh and baseline are never modified):
#   corrupt  restore.sh boots a damaged COPY of the baseline (first 64 MB zeroed) -> twin never boots
#   slow     the heal is given 20 s instead of 300 s -> gives up while the firmware is still booting
#   hung     QEMU is frozen (SIGSTOP) as soon as it starts -> twin never answers
# Expect every trial: outcome restore_failed, device held, quarantine still on after the engine exits,
# attacker blocked. After each trial the twin is released and restored normally before the next one.
# No attack traffic is sent. Pause the watchdog first. Output: reports/member2/E12_<time>.log/.csv + RESULT.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
TRIALS=${1:-5}; FAULTS=${2:-"corrupt slow hung"}; DEV=192.168.0.1; BR=br-twin
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"; SCR="$FIRMAE_DIR/scratch/${IID:-1}"
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S)
LOG="$OUT/E12_$TS.log"; CSV="$OUT/E12_$TS.csv"; : >"$LOG"
echo "fault,trial,outcome,held,rules_after,atk_after,seconds" >"$CSV"
WORK=$(mktemp -d /var/tmp/e12.XXXX); FREEZER=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
atk() { ip netns exec atk ping -c 1 -W 1 $DEV >/dev/null 2>&1 && echo reaches || echo blocked; }
alert() {
  python3 - >"$1" <<'EOF'
import json, time
t = time.time()
print(json.dumps({"alert_version": "1.0.0", "emitted_at_epoch": t, "type": "window", "synthetic": True,
  "alert_id": "e12-%.3f" % t, "window_id": int(t), "window_start_epoch": t - 5, "window_end_epoch": t,
  "device_ip": "192.168.0.1", "firmware_id": "DIR-868L_revB_2-05b02", "interface": "tap1_0.1",
  "threat_label": "malicious", "threat_probability": 0.9, "risk_score": 90, "p_xgboost": 0.9,
  "p_incremental": 0.9, "explanation": [], "fingerprint_schema": "2.0.0", "detector_action": "alert_only"}))
EOF
}
recover() {   # release, unfreeze/stop QEMU, normal heal; returns 0 when the twin answers again
  [ -n "$FREEZER" ] && { kill "$FREEZER" 2>/dev/null; FREEZER=""; }
  pkill -CONT -f qemu-system- 2>/dev/null
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  # A fault that cuts a heal short leaves restore.sh and FirmAE's run.sh running in the background with the
  # disk image mounted; the next boot then fails once ("umount ... target is busy"). Stop them first.
  tmux kill-session -t twin 2>/dev/null; sleep 1
  pkill -f "$FIRMAE_DIR/restore.sh" 2>/dev/null; pkill -f "restore_corrupt.sh" 2>/dev/null
  pkill -f "run.sh -r" 2>/dev/null; pkill -f "scratch/${IID:-1}/run.sh" 2>/dev/null
  pkill -f qemu-system- 2>/dev/null; sleep 3
  umount -l "$SCR/image" 2>/dev/null
  bash network/twin_net.sh clean >>"$LOG" 2>&1
  bash network/twin_net.sh heal >>"$LOG" 2>&1
  ping -c 2 -W 2 $DEV >/dev/null 2>&1
}
cleanup() { recover >/dev/null 2>&1; log "cleanup: twin answers: $(ping -c1 -W2 $DEV >/dev/null 2>&1 && echo yes || echo NO), rules left $(rules)"; rm -rf "$WORK"; }
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
[ "$(ovs-vsctl get controller $BR is_connected)" = true ] || { log "Ryu not connected"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active: python3 persond/containment.py --mode ryu release $DEV"; exit 1; }
ping -c 2 -W 2 $DEV >/dev/null 2>&1 || { log "twin not answering: bash network/twin_net.sh status"; exit 1; }
log "E12 restore faults, git $(git rev-parse --short HEAD), $TRIALS trial(s) each of: $FAULTS"

# fault inputs (copies / wrappers only)
if echo "$FAULTS" | grep -qw corrupt; then
  log "making a damaged COPY of the baseline in $WORK (the original is not touched)"
  cp --sparse=always "$SCR/image.baseline.raw" "$WORK/corrupt.raw"
  dd if=/dev/zero of="$WORK/corrupt.raw" bs=1M count=64 conv=notrunc status=none
  printf '#!/bin/bash\nBASELINE=%s exec bash %s/restore.sh\n' "$WORK/corrupt.raw" "$FIRMAE_DIR" >"$WORK/restore_corrupt.sh"
fi

for fault in $FAULTS; do
  for t in $(seq 1 "$TRIALS"); do
    case $fault in
      corrupt) RCMD="env HEAL_TRIES=1 HEAL_TIMEOUT=200 REAL_RESTORE=$WORK/restore_corrupt.sh bash network/twin_net.sh heal" ;;
      slow)    RCMD="env HEAL_TRIES=1 HEAL_TIMEOUT=20 bash network/twin_net.sh heal" ;;
      hung)    RCMD="env HEAL_TRIES=1 HEAL_TIMEOUT=200 bash network/twin_net.sh heal"
               ( OLD=$(pgrep -f qemu-system- | tr '\n' ' ')            # freeze the NEW emulator once it starts
                 for _ in $(seq 1 400); do
                   for p in $(pgrep -f qemu-system-); do
                     echo " $OLD " | grep -q " $p " || { kill -STOP "$p"; echo "froze qemu $p" >>"$LOG"; exit 0; }
                   done; sleep 0.5
                 done ) & FREEZER=$! ;;
    esac
    db="$WORK/$fault$t.db"; feed="$WORK/$fault$t.jsonl"; alert "$feed"; t0=$(date +%s)
    timeout 900 python3 -u persond/run_pipeline.py "$feed" --db "$db" --containment ryu --restore-cmd "$RCMD" >>"$LOG" 2>&1
    secs=$(( $(date +%s) - t0 ))
    OUTC=$(grep -o "this run: {[^}]*}" "$LOG" | tail -1 | grep -o "'[a-z_]*'" | tr -d "'" | head -1)
    HELD=$(python3 -c "import sqlite3; r=sqlite3.connect('$db').execute(\"select reason from device_state where status='held'\").fetchone(); print('yes' if r else 'no')")
    R=$(rules); A=$(atk)
    echo "$fault,$t,$OUTC,$HELD,$R,$A,$secs" >>"$CSV"
    log "$fault trial $t: outcome=$OUTC held=$HELD after engine exit: rules=$R atk=$A ($secs s)"
    recover && log "  recovered: twin answers again" || log "  WARNING: twin did not come back - run: sudo bash network/twin_net.sh heal"
  done
done

{ echo; echo "===== RESULT E12 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "expect every trial: outcome restore_failed, held yes, rules 16, atk blocked"
  awk -F, 'NR>1{n[$1]++; ok[$1]+=($3=="restore_failed" && $4=="yes" && $5>0 && $6=="blocked")}
           END{for(f in n) printf "%-8s %d/%d trials kept the twin isolated and held\n", f, ok[f], n[f]}' "$CSV"
} | tee -a "$LOG"
