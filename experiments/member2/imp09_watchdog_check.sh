#!/bin/bash
# experiments/member2/imp09_watchdog_check.sh — IMP-09: restores done by the WATCHDOG count toward the
# "3 heals in 10 minutes -> hold for a human" rule.
#
#   sudo bash experiments/member2/imp09_watchdog_check.sh        (~13-15 min, 3 real restores, no attack)
#
# A private watchdog (--no-http, so a slow web UI is not mistaken for a dead twin) writes its records to a
# private feed that the engine (run_pipeline --follow, containment ryu) reads. The twin's emulator is
# stopped three times; each time the watchdog notices and restores it. Expect: heals 1 and 2 recorded as
# watchdog heals, heal 3 -> the engine holds the twin and isolates it.
# Pause the main watchdog first. Output: reports/member2/IMP09_<time>.log + RESULT. Releases at the end.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
DEV=192.168.0.1; BR=br-twin
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S); LOG="$OUT/IMP09_$TS.log"; : >"$LOG"
WORK=$(mktemp -d); FEED="$WORK/alerts.jsonl"; DB="$WORK/threat.db"; : >"$FEED"; PID=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
rules() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
heals_seen() { grep -c '"event": "heal_ok"\|"event": "heal_failed"' "$FEED"; }
q() { python3 -c "import sqlite3,sys; print(sqlite3.connect('$DB').execute(sys.argv[1]).fetchone()[0])" "$1" 2>/dev/null; }
cleanup() {
  tmux kill-session -t wd_test 2>/dev/null
  [ -n "$PID" ] && { kill -INT "$PID" 2>/dev/null; sleep 3; kill -9 "$PID" 2>/dev/null; }
  python3 persond/containment.py --mode ryu release $DEV >>"$LOG" 2>&1
  ping -c 2 -W 2 $DEV >/dev/null 2>&1 || bash network/twin_net.sh heal >>"$LOG" 2>&1
  log "cleanup: twin answers $(ping -c1 -W2 $DEV >/dev/null 2>&1 && echo yes || echo NO), rules left $(rules)"; rm -rf "$WORK"
}
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the main watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
[ "$(rules)" = 0 ] || { log "containment already active"; exit 1; }
ping -c 2 -W 2 $DEV >/dev/null 2>&1 || { log "twin not answering"; exit 1; }
log "IMP-09 check, git $(git rev-parse --short HEAD)"

python3 -u persond/run_pipeline.py --follow "$FEED" --db "$DB" --containment ryu >>"$LOG" 2>&1 & PID=$!
tmux new-session -d -s wd_test "python3 -u '$ROOT/network/watchdog.py' --no-http --startup-grace 5 --alerts-out '$FEED' --health-file '$WORK/health.json' 2>&1 | tee -a '$WORK/watchdog.log'"
sleep 15
for n in 1 2 3; do
  before=$(heals_seen); log "stop the emulator ($n of 3) - the watchdog should notice and restore the twin"
  pkill -f qemu-system- 2>/dev/null
  for _ in $(seq 1 120); do [ "$(heals_seen)" -gt "$before" ] && break; sleep 5; done
  sleep 6
  log "  watchdog heals seen: $(heals_seen) | engine: heals stored $(q "select count(*) from heals where source='watchdog'"), held: $(q "select count(*) from device_state where status='held'") | rules $(rules)"
  # The watchdog escalates (stops healing) after 2 heals that do not keep the twin up for --stable (60 s),
  # counted after its 30 s grace, so the twin must stay up >90 s before the next stop (first run escalated at 35 s).
  [ "$n" -lt 3 ] && sleep 100          # 30 s watchdog grace + 60 s stable + margin
done
sleep 5
HEALS=$(q "select count(*) from heals where source='watchdog'"); HELD=$(q "select coalesce(max(reason),'no') from device_state where status='held'")
R=$(rules); A=$(ip netns exec atk ping -c1 -W1 $DEV >/dev/null 2>&1 && echo reaches || echo blocked)
{ echo; echo "===== RESULT IMP-09 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "watchdog heals stored by the engine: $HEALS (expect 3)"
  echo "held: $HELD (expect '3 heals within 10 min (incl. watchdog)')"
  echo "after the 3rd heal: rules=$R atk=$A (expect rules=12 atk=blocked)"
} | tee -a "$LOG"
