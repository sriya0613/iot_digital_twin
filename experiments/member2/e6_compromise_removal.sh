#!/bin/bash
# experiments/member2/e6_compromise_removal.sh — E6 / SYS-01: does a heal really remove a persistent compromise?
#
#   sudo bash experiments/member2/e6_compromise_removal.sh [TRIALS]     (default 10; ~3 min per trial)
#
# The twin's serial console has no shell, so the changes are planted on the twin's DISK (image.raw) while
# the twin is stopped, like malware that has written itself to flash:
#   file     a new file             /etc/e6_<id>
#   modify   a line appended to an existing file in /etc
#   autorun  a startup script       /etc/init0.d/S99e6.sh  that writes /etc/e6_ran_<id> when it runs at boot
# CONTROL (once): plant, boot WITHOUT rollback (Sriya's restore.sh with the current disk as its 'baseline')
#   -> the changes must still be on the disk afterwards, otherwise they are not persistent.
# TRIALS: stop the twin, plant, heal (twin_net.sh heal = restore.sh rollback) -> all three must be gone.
# Checks read the running twin's disk through a READ-ONLY mount in a private folder (never FirmAE's
# scratch/1/image), and the disk is always detached again before any restore.
# Only image.raw (the working disk, rewritten by every restore) is touched; the baseline never is.
# No attack traffic. Pause the watchdog first. Output: reports/member2/E6_<time>.log/.csv + RESULT.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
TRIALS=${1:-10}; DEV=192.168.0.1
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"; DISK="$FIRMAE_DIR/scratch/${IID:-1}/image.raw"
OUT="$ROOT/reports/member2"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S)
LOG="$OUT/E6_$TS.log"; CSV="$OUT/E6_$TS.csv"; : >"$LOG"; echo "phase,trial,id,file,modify,autorun,ran,heal_rc" >"$CSV"
MNT=$(mktemp -d /var/tmp/e6mnt.XXXX); WRAP=$(mktemp)
printf '#!/bin/bash\n# boot WITHOUT rollback: restore.sh copies the current disk onto itself\nBASELINE=%s exec bash %s/restore.sh\n' "$DISK" "$FIRMAE_DIR" >"$WRAP"
LOOP=""; MODFILE=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
attach() {   # attach ro|rw : the twin's disk at $MNT (private folder)
  local ro=""; [ "$1" = ro ] && ro="-r"
  LOOP=$(losetup $ro -Pf --show "$DISK") || return 1
  for _ in 1 2 3 4 5; do [ -b "${LOOP}p1" ] && break; sleep 1; done
  if [ "$1" = ro ]; then mount -o ro "${LOOP}p1" "$MNT"; else mount "${LOOP}p1" "$MNT"; fi
}
detach() {
  sync; for _ in 1 2 3 4 5; do umount "$MNT" 2>/dev/null && break; sleep 1; done
  mountpoint -q "$MNT" && umount -l "$MNT"
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; LOOP=""
}
stop_twin() { tmux kill-session -t twin 2>/dev/null; pkill -f qemu-system- 2>/dev/null; sleep 4; }
plant() {   # plant <id> (twin stopped)
  attach rw || { log "could not open the disk to plant"; return 1; }
  echo e6 > "$MNT/etc/e6_$1"
  echo "# e6 $1" >> "$MNT/$MODFILE"
  printf '#!/bin/sh\necho ran > /etc/e6_ran_%s\nsync\n' "$1" > "$MNT/etc/init0.d/S99e6.sh"
  chmod +x "$MNT/etc/init0.d/S99e6.sh"
  detach
}
check() {   # check <id> -> "file modify autorun ran" (0/1), read-only on the running twin's disk
  attach ro || { echo "? ? ? ?"; return; }
  local f=0 m=0 a=0 r=0
  [ -f "$MNT/etc/e6_$1" ] && f=1
  grep -q "# e6 $1" "$MNT/$MODFILE" 2>/dev/null && m=1
  [ -f "$MNT/etc/init0.d/S99e6.sh" ] && a=1
  [ -f "$MNT/etc/e6_ran_$1" ] && r=1
  detach; echo "$f $m $a $r"
}
heal() { if [ -n "${1:-}" ]; then REAL_RESTORE="$1" bash network/twin_net.sh heal >>"$LOG" 2>&1; else bash network/twin_net.sh heal >>"$LOG" 2>&1; fi; }
settle() { sleep 60; }   # let the firmware finish booting and flush its writes (autorun's file) to the disk
cleanup() { detach 2>/dev/null; rmdir "$MNT" 2>/dev/null; rm -f "$WRAP"; }
trap cleanup EXIT

tmux has-session -t watchdog 2>/dev/null && { log "pause the watchdog first: sudo tmux kill-session -t watchdog"; exit 1; }
ping -c 2 -W 2 $DEV >/dev/null 2>&1 || { log "twin not answering: bash network/twin_net.sh status"; exit 1; }
log "E6 compromise removal (offline plant, read-only checks), git $(git rev-parse --short HEAD), $TRIALS trials"

# which existing /etc file to modify, and is there an init0.d? (read-only look at the current disk)
attach ro || { log "STOP: cannot open the twin's disk read-only"; exit 2; }
for f in etc/profile etc/services etc/inittab etc/passwd; do [ -f "$MNT/$f" ] && { MODFILE=$f; break; }; done
INIT=$([ -d "$MNT/etc/init0.d" ] && echo yes || echo no)
log "disk: $(ls "$MNT" | tr '\n' ' ')| modify target: ${MODFILE:-none} | /etc/init0.d present: $INIT"
detach
[ -n "$MODFILE" ] && [ "$INIT" = yes ] || { log "STOP: no file to modify or no /etc/init0.d on the disk"; exit 2; }

# ---- control: planted changes survive a boot without rollback?
ID="ctl$TS"; stop_twin; plant "$ID" || exit 2
log "CONTROL planted on the stopped twin's disk; booting WITHOUT rollback"
heal "$WRAP"; RC=$?; settle
C=$(check "$ID"); echo "control,0,$ID,$(echo $C | tr ' ' ','),$RC" >>"$CSV"
log "CONTROL after boot without rollback (rc $RC): file/modify/autorun/ran = $C   (expect 1 1 1 1)"

# ---- trials: plant -> heal (rollback) -> gone?
for t in $(seq 1 "$TRIALS"); do
  ID="t${t}_$TS"; stop_twin; plant "$ID" || { log "trial $t: plant failed"; continue; }
  heal; RC=$?; settle
  A=$(check "$ID"); echo "trial,$t,$ID,$(echo $A | tr ' ' ','),$RC" >>"$CSV"
  log "trial $t: after heal (rc $RC) file/modify/autorun/ran = $A   (expect 0 0 0 0)"
done

{ echo; echo "===== RESULT E6 ($TS, git $(git rev-parse --short HEAD)) ====="
  echo "control (boot WITHOUT rollback): file/modify/autorun/ran = $C   (expect 1 1 1 1: the changes persist and the autorun runs)"
  awk -F, '$1=="trial"{n++; f+=$4; m+=$5; a+=$6; r+=$7; if($8!=0) bad++} END{printf "trials %d: still present after heal: file %d, modify %d, autorun %d, autorun ran %d (expect 0 each); heals failed %d\n", n, f, m, a, r, bad+0}' "$CSV"
} | tee -a "$LOG"
