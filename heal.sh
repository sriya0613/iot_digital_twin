#!/bin/bash
# heal.sh — run Person 1's restore.sh DETACHED from the terminal.
#
# restore.sh starts the emulator as a background child of whatever terminal ran it.
# That leaves the twin tied to the terminal: Ctrl-C there kills it, it switches the
# terminal to raw mode, and when restore.sh is run by hand the twin can die a minute
# or two later, as soon as the terminal is used again. Running the restore in its own
# session (setsid) with no keyboard input (< /dev/null) cuts that tie.
#
#   ./heal.sh        restore the twin to its clean baseline and reboot it (1.5 - 4 min)
#
# Exit code is restore.sh's: 0 = device healthy again.
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
RESTORE="${RESTORE:-$FIRMAE_DIR/restore.sh}"
[ -f "$RESTORE" ] || { echo "[heal] not found: $RESTORE"; exit 1; }
# restore.sh writes its boot log to /tmp/firmae_restore.log. Linux refuses to let root
# write to a file in /tmp that another user owns, so clear the old one first and hand
# the new one back to the normal user afterwards (so restore.sh still works by hand).
BOOTLOG=/tmp/firmae_restore.log
ME="$(id -un)"
sudo rm -f "$BOOTLOG"
sudo setsid --wait env FIRMAE_DIR="$FIRMAE_DIR" IID="${IID:-1}" bash "$RESTORE" < /dev/null
CODE=$?
sudo chown "$ME" "$BOOTLOG" 2>/dev/null
exit $CODE
