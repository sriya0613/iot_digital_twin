#!/bin/bash
# network/restore_verified.sh — the restore (self-healing hook) with proof that the disk was rolled back.
#
# Does exactly what ~/firmae/FirmAE/restore.sh does (stop the emulator, copy the clean baseline over the
# disk, reboot through FirmAE, wait for 192.168.0.1), plus ONE step between copy and boot: hash the disk
# the twin is about to boot and write the result to network/.state/last_restore.json. The verifier
# (persond/verify_heal.py, check "disk") compares that hash with the registered clean hash (IMP-05).
#
# After the boot the firmware writes to image.raw, so its hash changes even on a perfect heal; the only
# point where "the twin runs from a clean disk" can be checked by hash is here, before the boot.
#
# OPT-IN, NOT THE DEFAULT: sudo REAL_RESTORE=$PWD/network/restore_verified.sh bash network/twin_net.sh heal
# On 2026-11-26 (Member 2's VM) FirmAE's boot failed after this script ("umount: .../scratch/1/image: target
# is busy", no emulator) while ~/firmae/FirmAE/restore.sh booted every time; cause not yet understood.
# Exit 0 = twin answers again.
set -euo pipefail

IID="${IID:-1}"
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
SCRATCH="${SCRATCH:-${FIRMAE_DIR}/scratch/${IID}}"
DISK="${DISK:-${SCRATCH}/image.raw}"
BASELINE="${BASELINE:-${SCRATCH}/image.baseline.raw}"
BRAND="${BRAND:-dlink}"
FIRMWARE="${FIRMWARE:-${FIRMAE_DIR}/firmwares/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${STATE:-$HERE/.state}"; mkdir -p "$STATE"
RECORD="$STATE/last_restore.json"
REGISTRY="$STATE/baseline.sha256"

[ -f "$BASELINE" ] || { echo "[!] no baseline found: $BASELINE — run ./save_baseline.sh first"; exit 1; }
echo "[*] $(date '+%H:%M:%S') SELF-HEAL: reverting device to clean baseline"

# 1) stop the (possibly compromised) running device
echo "[*] stopping current emulation..."
sudo pkill -f qemu-system-arm 2>/dev/null || true
sleep 3

# 2) roll the disk back to the golden baseline
echo "[*] restoring disk image from baseline..."
rm -f "$RECORD"                                   # no stale proof from an earlier restore
T0=$(date +%s.%N)
cp --sparse=always "$BASELINE" "${DISK}.tmp"
mv -f "${DISK}.tmp" "$DISK"
echo "[+] disk reverted."

# 2b) proof: hash the disk the twin is about to boot (IMP-05)
GOT=$(sha256sum "$DISK" | cut -d' ' -f1)
WANT=$( [ -f "$REGISTRY" ] && cut -d' ' -f1 "$REGISTRY" || echo "")
T1=$(date +%s.%N)
printf '{"copied_at_epoch": %s, "hashed_seconds": %s, "disk": "%s", "disk_sha256": "%s", "registered_sha256": "%s", "match": %s}\n' \
  "$T0" "$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.1f", b-a}')" "$DISK" "$GOT" "$WANT" \
  "$( [ -n "$WANT" ] && [ "$GOT" = "$WANT" ] && echo true || echo false )" > "$RECORD"
chmod a+r "$RECORD"
if [ -z "$WANT" ]; then echo "[!] no registered clean hash ($REGISTRY): run python3 persond/verify_heal.py --register-baseline"
elif [ "$GOT" = "$WANT" ]; then echo "[+] disk sha256 ${GOT:0:16} matches the registered clean baseline"
else echo "[!] disk sha256 ${GOT:0:16} != registered ${WANT:0:16} — baseline changed or copy failed"; fi

# 3) reboot the device through FirmAE (so networking is set up properly)
echo "[*] rebooting device via FirmAE... (boot log: /tmp/firmae_restore.log)"
cd "$FIRMAE_DIR"
sudo ./run.sh -r "$BRAND" "$FIRMWARE" > /tmp/firmae_restore.log 2>&1 &

# 4) wait for it to come back (same timing as restore.sh)
echo "[*] giving the firmware time to boot (initial 60s settle)..."
sleep 60
echo "[*] waiting for 192.168.0.1 to respond..."
for i in $(seq 1 90); do
  if ping -c1 -W1 192.168.0.1 >/dev/null 2>&1; then
    echo "[+] $(date '+%H:%M:%S') device healthy again after ~$(( 60 + i*2 ))s."
    exit 0
  fi
  sleep 2
done
echo "[!] device did not respond within ~4min — check ${SCRATCH}/qemu.final.serial.log"
exit 1
