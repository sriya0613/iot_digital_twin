#!/bin/bash
# experiments/member2/isolate_retry_check.sh — E11 part B with the engine: an isolate that fails because
# Ryu is down must be retried until it succeeds (healing engine, E11 follow-up).
#
#   sudo bash experiments/member2/isolate_retry_check.sh        (~2 min, no attack, the twin is NOT restored)
#
# 1. stop Ryu (only Ryu: the twin keeps running; fail_mode secure keeps normal switching)
# 2. feed the engine one high-risk alert; its restore is the command 'false' (fails at once, no restore),
#    so the device is held and its isolate is still owed
# 3. start Ryu again, feed calm alerts every 5 s -> the engine must install the quarantine by itself
# 4. stop the engine -> the quarantine must stay
# Output: reports/member2/RETRY_<time>.log with a RESULT block. Releases everything at the end.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
DEV=192.168.0.1; BR=br-twin
RYU="${RYU_MANAGER:-/home/${SUDO_USER:-vboxuser}/ryu-venv/bin/ryu-manager}"
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S); LOG="$OUT/RETRY_$TS.log"; : >"$LOG"
WORK=$(mktemp -d); FEED="$WORK/alerts.jsonl"; DB="$WORK/threat.db"; : >"$FEED"; PID=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
atk() { ip netns exec atk ping -c 1 -W 1 $DEV >/dev/null 2>&1 && echo reaches || echo blocked; }
ryu_up() { [ "$(ovs-vsctl get controller $BR is_connected 2>/dev/null)" = true ]; }
start_ryu() {   # same command as twin_net.sh up, without starting the watchdog
  tmux has-session -t ryu 2>/dev/null || tmux new-session -d -s ryu \
    "cd '$ROOT' && '$RYU' --wsapi-host 127.0.0.1 ryu.app.ofctl_rest network/ryu_base.py 2>&1 | tee -a network/.state/ryu.log"
  for _ in $(seq 1 30); do ryu_up && curl -s -m 2 http://127.0.0.1:8080/stats/switches >/dev/null && return 0; sleep 1; done; return 1
}
stop_ryu() { tmux kill-session -t ryu 2>/dev/null; sleep 1; pkill -f 'python[0-9.]* [^ ]*ryu-manager' 2>/dev/null; sleep 2; }
alert() {
  python3 - "$1" >>"$FEED" <<'EOF'
import json, sys, time
r = int(sys.argv[1]); t = time.time()
print(json.dumps({"alert_version": "1.0.0", "emitted_at_epoch": t, "type": "window", "synthetic": True,
  "alert_id": "retry-%.3f" % t, "window_id": int(t), "window_start_epoch": t - 5, "window_end_epoch": t,
  "device_ip": "192.168.0.1", "firmware_id": "DIR-868L_revB_2-05b02", "interface": "tap1_0.1",
  "threat_label": "malicious" if r > 70 else "benign", "threat_probability": r / 100, "risk_score": r,
  "p_xgboost": r / 100, "p_incremental": r / 100, "explanation": [], "fingerprint_schema": "2.0.0",
  "detector_action": "alert_only"}))
EOF
}
cleanup() {
  [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null
  ryu_up || start_ryu >/dev/null
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  log "cleanup: Ryu connected=$(ryu_up && echo yes || echo no), rules left $(rules) (expect 0)"; rm -rf "$WORK"
}
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
ryu_up || { log "Ryu not connected: start the twin network first"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active: python3 persond/containment.py --mode ryu release $DEV"; exit 1; }
log "isolate-retry check, git $(git rev-parse --short HEAD); before: rules=$(rules) atk=$(atk)"

stop_ryu; log "Ryu stopped: connected=$(ryu_up && echo yes || echo no); twin still reached by atk: $(atk)"
python3 -u -c 'import runpy, signal, sys
signal.signal(signal.SIGINT, signal.default_int_handler)
sys.argv = ["persond/run_pipeline.py"] + sys.argv[1:]
runpy.run_path("persond/run_pipeline.py", run_name="__main__")' \
  --follow "$FEED" --db "$DB" --containment ryu --restore-cmd false >>"$LOG" 2>&1 & PID=$!; sleep 3
alert 90; sleep 12
S1="rules=$(rules) atk=$(atk)"
NOTE=$(python3 -c "import sqlite3; print(sqlite3.connect('$DB').execute(\"select count(*) from escalations where reason like 'isolate failed%'\").fetchone()[0])")
log "alert handled with Ryu down: $S1, 'isolate failed' notifications: $NOTE"
start_ryu || log "WARNING: Ryu did not come back"; T_RYU=$(date +%s)
log "Ryu started again (connected=$(ryu_up && echo yes || echo no)); feeding calm alerts every 5 s"
T_OK=""
for i in $(seq 1 6); do
  alert 5; sleep 5
  if [ -z "$T_OK" ] && [ "$(rules)" -gt 0 ]; then T_OK=$(( $(date +%s) - T_RYU )); fi
  log "  calm alert $i: rules=$(rules) atk=$(atk)"
done
S2="rules=$(rules) atk=$(atk)"
kill -INT "$PID"; for _ in $(seq 1 15); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done; kill -9 "$PID" 2>/dev/null; PID=""
S3="rules=$(rules) atk=$(atk)"
log "engine stopped: $S3"

{ echo; echo "===== RESULT isolate retry ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "with Ryu down:            $S1 (expect rules=0, atk reaches; notifications >= 1: $NOTE)"
  echo "after Ryu is back:        $S2 (expect rules=16 atk=blocked), quarantine installed ${T_OK:-never} s after Ryu returned"
  echo "after the engine stopped: $S3 (expect rules=16 atk=blocked)"
} | tee -a "$LOG"
