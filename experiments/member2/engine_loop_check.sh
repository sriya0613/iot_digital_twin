#!/bin/bash
# experiments/member2/engine_loop_check.sh — the whole response loop on the twin (IMP-05/06, SYS-01, SYS-08).
#
#   sudo bash experiments/member2/engine_loop_check.sh        (~10-12 min, two REAL restores, no attack sent)
#
# The engine (persond/run_pipeline.py: containment ryu, verify full, real restore through twin_net.sh heal)
# is fed one synthetic high-risk alert per part. While it works, the switch and reachability are sampled
# every 5 s (our rules, attacker -> twin, host -> twin).
#   P  all checks can pass       -> expect: isolated during restore, checks while isolated pass,
#                                   released, after-release checks pass, outcome "restored"
#   F  a check is made to fail   -> --accept-http 999 (the web UI never returns 999): expect the
#      while isolated               device to STAY isolated and be held for a human (IMP-06); no release
# Pause the watchdog first (sudo tmux kill-session -t watchdog) so it cannot restart the twin meanwhile.
# Output: reports/member2/LOOP_<time>.log, LOOP_<time>.csv (samples) and a RESULT block.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
DEV=192.168.0.1; BR=br-twin; SERVICE_TIMEOUT=${SERVICE_TIMEOUT:-300}
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S)
LOG="$OUT/LOOP_$TS.log"; CSV="$OUT/LOOP_$TS.csv"; : >"$LOG"; echo "part,t_s,rules,atk,host" >"$CSV"
WORK=$(mktemp -d); SAMPLER=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
reach() { ip netns exec "$1" ping -c 1 -W 1 $DEV >/dev/null 2>&1 && echo 1 || echo 0; }
hreach() { ping -c 1 -W 1 $DEV >/dev/null 2>&1 && echo 1 || echo 0; }
alert() {   # alert <file> <risk>
  python3 - "$2" >>"$1" <<'EOF'
import json, sys, time
r = int(sys.argv[1]); t = time.time()
print(json.dumps({"alert_version": "1.0.0", "emitted_at_epoch": t, "type": "window", "synthetic": True,
  "alert_id": "loop-%.3f" % t, "window_id": int(t), "window_start_epoch": t - 5, "window_end_epoch": t,
  "device_ip": "192.168.0.1", "firmware_id": "DIR-868L_revB_2-05b02", "interface": "tap1_0.1",
  "threat_label": "malicious", "threat_probability": r / 100, "risk_score": r, "p_xgboost": r / 100,
  "p_incremental": r / 100, "explanation": [], "fingerprint_schema": "2.0.0", "detector_action": "alert_only"}))
EOF
}
sample() {   # sample <part> : every 5 s until killed
  local t0; t0=$(date +%s)
  while true; do echo "$1,$(( $(date +%s) - t0 )),$(rules),$(reach atk),$(hreach)" >>"$CSV"; sleep 4; done
}
summ() {   # summ <part> : what the samples show while our rules were on the switch
  awk -F, -v p="$1" '$1==p && $3>0 {n++; a+=$4; h+=$5} END {printf "%d samples isolated: attacker reached twin %d, host reached twin %d", n, a, h}' "$CSV"
}
run_part() {   # run_part <P|F> <extra engine args...>
  local part=$1; shift; local feed="$WORK/$part.jsonl" db="$WORK/$part.db"; : >"$feed"; alert "$feed" 90
  sample "$part" & SAMPLER=$!
  timeout 1200 python3 -u persond/run_pipeline.py "$feed" --db "$db" --containment ryu --verify full \
    --restore-cmd "bash network/twin_net.sh heal" --service-timeout "$SERVICE_TIMEOUT" \
    --client-cmd "ip netns exec cli ping -c1 -W1 $DEV" "$@" >>"$LOG" 2>&1
  sleep 5; kill $SAMPLER 2>/dev/null; wait $SAMPLER 2>/dev/null; SAMPLER=""
  OUTCOME=$(grep -o "this run: {[^}]*}" "$LOG" | tail -1)
  CHECKS=$(python3 -c "import sqlite3; print(sqlite3.connect('$db').execute(\"select group_concat(factor||'='||coalesce(ok,'skip'),' ') from heal_checks\").fetchone()[0])")
  HELD=$(python3 -c "import sqlite3; r=sqlite3.connect('$db').execute(\"select reason from device_state where status='held'\").fetchone(); print(r[0] if r else 'no')")
  END="rules=$(rules) atk=$(reach atk) host=$(hreach)"
  log "$part engine: $OUTCOME | checks: $CHECKS | held: $HELD | after engine exit: $END | $(summ "$part")"
  eval "R_$part=\"outcome $OUTCOME; checks $CHECKS; held: $HELD; after exit $END; $(summ "$part")\""
}
cleanup() {
  [ -n "$SAMPLER" ] && kill $SAMPLER 2>/dev/null
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  log "cleanup: rules left $(rules) (expect 0)"; rm -rf "$WORK"
}
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "watchdog is running - pause it first: sudo tmux kill-session -t watchdog"; exit 1; }
[ "$(ovs-vsctl get controller $BR is_connected)" = true ] || { log "Ryu not connected: sudo bash network/twin_net.sh up"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active: python3 persond/containment.py --mode ryu release $DEV"; exit 1; }
[ "$(hreach)" = 1 ] || { log "twin not answering: sudo bash network/twin_net.sh status"; exit 1; }
[ -f network/.state/baseline.sha256 ] || { log "no registered baseline: python3 persond/verify_heal.py --register-baseline"; exit 1; }
log "engine loop check, git $(git rev-parse --short HEAD), service timeout ${SERVICE_TIMEOUT}s"

log "P: one alert, real restore, all checks may pass"
run_part P
for _ in $(seq 1 60); do [ "$(hreach)" = 1 ] && break; sleep 5; done
log "F: one alert, real restore, service check forced to fail (--accept-http 999)"
run_part F --accept-http 999 --service-timeout 30

{ echo; echo "===== RESULT engine loop ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "P (all checks can pass):  ${R_P:-not run}"
  echo "F (check forced to fail): ${R_F:-not run}"
  echo "expect P: restored, checks all =1, held no, after exit rules=0, attacker 0 while isolated"
  echo "expect F: restored_checks_failed, service=0, held yes, after exit rules=12 atk=0, attacker 0 while isolated"
} | tee -a "$LOG"
