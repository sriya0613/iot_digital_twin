#!/bin/bash
# experiments/member2/imp10_background_check.sh — IMP-10: does the engine keep deciding while it restores?
#
#   sudo bash experiments/member2/imp10_background_check.sh        (~7-8 min, 2 real restores, no attack)
#
# Twice, once with restores in the foreground (old behaviour) and once with --background-restore:
#   1. one high-risk alert for the twin -> the engine isolates it and starts a REAL restore
#   2. 10 s later, a low-risk alert for another device (192.168.0.20) -> measure how long until the
#      engine records a decision for it
# Expect: foreground ~ the whole restore (about 2 min); background a few seconds. Both restores must still
# finish and release the twin. Pause the watchdog first. Output: reports/member2/IMP10_<time>.log + RESULT.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
DEV=192.168.0.1; BR=br-twin
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S); LOG="$OUT/IMP10_$TS.log"; : >"$LOG"
WORK=$(mktemp -d); PID=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
alert() {   # alert <feed> <ip> <risk> <id>
  python3 - "$2" "$3" "$4" >>"$1" <<'EOF'
import json, sys, time
ip, r, aid = sys.argv[1], int(sys.argv[2]), sys.argv[3]; t = time.time()
print(json.dumps({"alert_version": "1.0.0", "emitted_at_epoch": t, "type": "window", "synthetic": True,
  "alert_id": aid, "window_id": int(t), "window_start_epoch": t - 5, "window_end_epoch": t,
  "device_ip": ip, "firmware_id": "DIR-868L_revB_2-05b02", "interface": "tap1_0.1",
  "threat_label": "malicious" if r > 70 else "benign", "threat_probability": r / 100, "risk_score": r,
  "p_xgboost": r / 100, "p_incremental": r / 100, "explanation": [], "fingerprint_schema": "2.0.0",
  "detector_action": "alert_only"}))
EOF
}
decided() { python3 -c "import sqlite3,sys; r=sqlite3.connect(sys.argv[1]).execute('select count(*) from actions where alert_id=?',(sys.argv[2],)).fetchone(); print(r[0])" "$1" "$2" 2>/dev/null || echo 0; }
heals() { python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"select count(*) || ' ok=' || coalesce(sum(ok),0) from heals\").fetchone()[0])" "$1" 2>/dev/null; }
run() {   # run <name> [engine flags] -> sets RES_<name>
  local name=$1; shift; local feed="$WORK/$name.jsonl" db="$WORK/$name.db"; : >"$feed"
  python3 -u persond/run_pipeline.py --follow "$feed" --db "$db" --containment ryu \
    --restore-cmd "bash network/twin_net.sh heal" "$@" >>"$LOG" 2>&1 & PID=$!; sleep 3
  alert "$feed" $DEV 90 "$name-twin"; sleep 10
  local t0; t0=$(date +%s.%N); alert "$feed" 192.168.0.20 10 "$name-other"
  for _ in $(seq 1 400); do [ "$(decided "$db" "$name-other")" = 1 ] && break; sleep 0.5; done
  local lat; lat=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
  log "$name: decision for the other device after $lat s"
  for _ in $(seq 1 60); do alert "$feed" $DEV 5 "$name-calm-$_"; sleep 5          # keep records coming so a
    [ "$(rules)" = 0 ] && ping -c1 -W1 $DEV >/dev/null 2>&1 && break; done           # background result is applied
  log "$name: twin released and answering: rules=$(rules), heals $(heals "$db")"
  kill -INT "$PID" 2>/dev/null; sleep 3; kill -9 "$PID" 2>/dev/null; PID=""
  eval "RES_$name=\"other-device decision after $lat s; heals $(heals "$db"); rules after=$(rules)\""
}
cleanup() {
  [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  ping -c 2 -W 2 $DEV >/dev/null 2>&1 || bash network/twin_net.sh heal >>"$LOG" 2>&1
  log "cleanup: twin answers $(ping -c1 -W2 $DEV >/dev/null 2>&1 && echo yes || echo NO), rules left $(rules)"; rm -rf "$WORK"
}
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active"; exit 1; }
ping -c 2 -W 2 $DEV >/dev/null 2>&1 || { log "twin not answering"; exit 1; }
log "IMP-10 check, git $(git rev-parse --short HEAD)"
run fg
run bg --background-restore
{ echo; echo "===== RESULT IMP-10 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "foreground restore: ${RES_fg:-not run}   (expect: decision only after the restore, ~2 min)"
  echo "background restore: ${RES_bg:-not run}   (expect: decision within a few seconds)"
} | tee -a "$LOG"
