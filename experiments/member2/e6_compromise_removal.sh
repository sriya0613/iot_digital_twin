#!/bin/bash
# experiments/member2/e6_compromise_removal.sh — E6 / SYS-01: does a heal really remove a persistent compromise?
#
#   sudo bash experiments/member2/e6_compromise_removal.sh [TRIALS]     (default 10; ~2.5 min per trial)
#
# Inside the twin (through FirmAE's serial console, experiments/member2/twin_console.py) three persistent
# changes are planted, like malware that wants to survive a reboot:
#   file     a new file            /etc/e6_<id>
#   modify   a line appended to an existing file in /etc
#   autorun  a startup script      /etc/init0.d/S99e6.sh  that writes /var/e6_ran_<id> at every boot
# CONTROL (once): plant, then reboot WITHOUT rollback (restore.sh with the current disk as its 'baseline',
#   i.e. Sriya's script unchanged) -> the changes must still be there, otherwise they are not persistent
#   and their removal proves nothing.
# TRIALS: plant, check present, heal (twin_net.sh heal = restore.sh rollback), check all three are gone.
# No attack traffic is sent. Pause the watchdog first. Output: reports/member2/E6_<time>.log/.csv + RESULT.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
TRIALS=${1:-10}; DEV=192.168.0.1
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"; DISK="$FIRMAE_DIR/scratch/${IID:-1}/image.raw"
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S)
LOG="$OUT/E6_$TS.log"; CSV="$OUT/E6_$TS.csv"; : >"$LOG"; echo "phase,trial,id,file,modify,autorun,heal_rc" >"$CSV"
CON="python3 $HERE/twin_console.py"
WRAP=$(mktemp); printf '#!/bin/bash\n# reboot WITHOUT rollback: restore.sh copies the current disk onto itself\nBASELINE=%s exec bash %s/restore.sh\n' "$DISK" "$FIRMAE_DIR" >"$WRAP"
MODFILE=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
console_ready() { for _ in $(seq 1 40); do $CON --probe >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }
plant() {   # plant <id>
  $CON "echo e6 > /etc/e6_$1; echo '# e6 $1' >> $MODFILE; printf '#!/bin/sh\necho ran > /var/e6_ran_$1\n' > /etc/init0.d/S99e6.sh; chmod +x /etc/init0.d/S99e6.sh; sync" >>"$LOG" 2>&1
}
present() {   # present <id> -> "file modify autorun" as 0/1 each ; autorun = script present AND it ran this boot
  local f m a
  f=$($CON "[ -f /etc/e6_$1 ] && echo Y || echo N" 2>/dev/null | tail -1)
  m=$($CON "grep -q '# e6 $1' $MODFILE && echo Y || echo N" 2>/dev/null | tail -1)
  a=$($CON "[ -f /etc/init0.d/S99e6.sh ] && echo Y || echo N" 2>/dev/null | tail -1)
  echo "$([ "$f" = Y ] && echo 1 || echo 0) $([ "$m" = Y ] && echo 1 || echo 0) $([ "$a" = Y ] && echo 1 || echo 0)"
}
ran_at_boot() { [ "$($CON "[ -f /var/e6_ran_$1 ] && echo Y || echo N" 2>/dev/null | tail -1)" = Y ] && echo 1 || echo 0; }
heal() {   # heal [restore-script] -> exit code of twin_net.sh heal
  if [ -n "${1:-}" ]; then REAL_RESTORE="$1" bash network/twin_net.sh heal >>"$LOG" 2>&1; else bash network/twin_net.sh heal >>"$LOG" 2>&1; fi
}
trap 'rm -f "$WRAP"' EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
ping -c 2 -W 2 $DEV >/dev/null 2>&1 || { log "twin not answering: bash network/twin_net.sh status"; exit 1; }
log "E6 compromise removal, git $(git rev-parse --short HEAD), $TRIALS trials"
if ! console_ready; then
  log "STOP: no shell answers on the twin's serial console (/tmp/qemu.1.S1). E6 needs a way to run commands"
  log "      inside the twin; paste this log and the output of: sudo ls -l /tmp/qemu.1*"
  exit 2
fi
log "console: $($CON 'id; mount | grep -E " / | /etc | /var " | head -3' 2>&1 | tr '\n' ' ')"
for f in /etc/profile /etc/services /etc/inittab /etc/passwd /etc/hosts; do
  [ "$($CON "[ -f $f ] && [ -w $f ] && echo Y || echo N" | tail -1)" = Y ] && { MODFILE=$f; break; }
done
[ -n "$MODFILE" ] || { log "STOP: no writable file found in /etc for the 'modify' change"; exit 2; }
log "modify target: $MODFILE"

# ---- control: are the changes persistent across a reboot without rollback?
ID="ctl$TS"; plant "$ID"; P=$(present "$ID")
log "CONTROL planted: file/modify/autorun = $P"
heal "$WRAP"; RC=$?; console_ready || log "WARNING: console not back after the control reboot"
P2=$(present "$ID"); R=$(ran_at_boot "$ID")
echo "control,0,$ID,$(echo $P2 | tr ' ' ','),$RC" >>"$CSV"
log "CONTROL after reboot WITHOUT rollback (rc $RC): file/modify/autorun = $P2, autorun ran at boot = $R"
CTRL="$P2 ran=$R"

# ---- trials: plant -> heal (rollback) -> gone?
for t in $(seq 1 "$TRIALS"); do
  ID="t${t}_$TS"; plant "$ID"; P=$(present "$ID")
  heal; RC=$?; console_ready || log "WARNING: console not back after heal $t"
  A=$(present "$ID"); R=$(ran_at_boot "$ID")
  echo "trial,$t,$ID,$(echo $A | tr ' ' ','),$RC" >>"$CSV"
  log "trial $t: before heal $P | after heal (rc $RC) file/modify/autorun = $A, autorun ran = $R"
done

{ echo; echo "===== RESULT E6 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "control (reboot without rollback), still present: file/modify/autorun = $CTRL   (expect 1 1 1 ran=1)"
  awk -F, '$1=="trial"{n++; f+=$4; m+=$5; a+=$6; if($7!=0) bad++} END{printf "trials %d: still present after heal: file %d, modify %d, autorun %d (expect 0 each); heals failed %d\n", n, f, m, a, bad+0}' "$CSV"
} | tee -a "$LOG"
