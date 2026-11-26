#!/bin/bash
# experiments/member2/imp11_check.sh — IMP-11: does the healing engine keep its state across a stop?
#
#   sudo bash experiments/member2/imp11_check.sh        (~2 min, twin + Ryu up, no attack is sent)
#
# The engine (persond/run_pipeline.py, containment ryu) is fed a synthetic high-risk alert, so it
# isolates the twin and starts a restore (a fake 45 s 'sleep', the twin itself is not touched).
#   A  stop it with Ctrl-C (SIGINT) mid-restore      -> are the quarantine rules still on the switch?
#   B  kill it (SIGKILL, = crash) mid-restore, restart it, feed a low-risk alert
#                                                     -> does the new engine know the twin is isolated?
# Output: reports/member2/IMP11_<time>.log with a RESULT block.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
DEV=192.168.0.1; BR=br-twin
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S); LOG="$OUT/IMP11_$TS.log"; : >"$LOG"
WORK=$(mktemp -d); FEED="$WORK/alerts.jsonl"; DB="$WORK/threat.db"; : >"$FEED"
PID=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
atk() { ip netns exec atk ping -c 1 -W 1 $DEV >/dev/null 2>&1 && echo reaches || echo blocked; }
alert() {   # alert <risk> : append one synthetic window alert stamped now
  python3 - "$1" >>"$FEED" <<'EOF'
import json, sys, time
r = int(sys.argv[1]); t = time.time()
print(json.dumps({"alert_version": "1.0.0", "emitted_at_epoch": t, "type": "window", "synthetic": True,
  "alert_id": "imp11-%.3f" % t, "window_id": int(t), "window_start_epoch": t - 5, "window_end_epoch": t,
  "device_ip": "192.168.0.1", "firmware_id": "DIR-868L_revB_2-05b02", "interface": "tap1_0.1",
  "threat_label": "malicious" if r > 70 else "benign", "threat_probability": r / 100, "risk_score": r,
  "p_xgboost": r / 100, "p_incremental": r / 100, "explanation": [], "fingerprint_schema": "2.0.0",
  "detector_action": "alert_only"}))
EOF
}
start_engine() {
  # Background jobs of a script start with Ctrl-C (SIGINT) ignored, and Python keeps an ignored SIGINT,
  # so restore Python's normal Ctrl-C handling before running the pipeline.
  python3 -u -c 'import runpy, signal, sys
signal.signal(signal.SIGINT, signal.default_int_handler)
sys.argv = ["persond/run_pipeline.py"] + sys.argv[1:]
runpy.run_path("persond/run_pipeline.py", run_name="__main__")' \
    --follow "$FEED" --db "$DB" --containment ryu --restore-cmd "sleep 45" >>"$LOG" 2>&1 & PID=$!; sleep 3
}
stop_engine() {   # stop_engine INT|KILL : send the signal, wait at most 15 s, then make sure it is gone
  kill -"$1" "$PID" 2>/dev/null
  for _ in $(seq 1 15); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
  kill -0 "$PID" 2>/dev/null && { log "  engine ignored SIG$1 for 15 s - killing it"; kill -9 "$PID"; }
  wait "$PID" 2>/dev/null; PID=""
}
cleanup() {
  [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  log "cleanup: rules left $(rules) (expect 0)"; rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(ovs-vsctl get controller $BR is_connected)" = true ] || { log "Ryu not connected: sudo bash network/twin_net.sh up"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active: python3 persond/containment.py --mode ryu release $DEV"; exit 1; }
log "IMP-11 check, git $(git rev-parse --short HEAD); before: rules=$(rules) atk=$(atk)"

# ---- A: graceful stop (Ctrl-C) during the restore
start_engine; alert 90; sleep 6
A0="rules=$(rules) atk=$(atk)"; log "A  engine isolated the twin and is restoring: $A0"
stop_engine INT; sleep 2
A1="rules=$(rules) atk=$(atk)"; log "A  after Ctrl-C mid-restore: $A1"
python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1; sleep 2

# ---- B: crash (SIGKILL) during the restore, then restart
start_engine; alert 90; sleep 6
B0="rules=$(rules) atk=$(atk)"; log "B  engine isolated the twin and is restoring: $B0"
stop_engine KILL; sleep 2
B1="rules=$(rules) atk=$(atk)"; log "B  after crash mid-restore: $B1"
start_engine
for i in 1 2 3; do alert 5; sleep 4; done           # calm windows: a stateful engine would release + verify
sleep 50                                             # past the fake restore time
B2="rules=$(rules) atk=$(atk)"; log "B  restarted engine, 3 low-risk alerts, 60 s later: $B2"
HEALS=$(python3 -c "import sqlite3;print(sqlite3.connect('$DB').execute('select count(*), coalesce(group_concat(verify_status),\"\") from heals').fetchone())")
log "B  heals in database: $HEALS"
stop_engine INT
B3="rules=$(rules) atk=$(atk)"; log "B  after stopping the restarted engine with Ctrl-C: $B3"

{ echo; echo "===== RESULT IMP-11 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "A  isolate+restoring: $A0 | after Ctrl-C: $A1"
  echo "B  isolate+restoring: $B0 | after crash: $B1 | restarted + 3 calm alerts: $B2 | restarted engine stopped: $B3"
  echo "B  heals in db (count, verify statuses): $HEALS"
} | tee -a "$LOG"
