#!/bin/bash
# network/heal_bridged.sh — the restore command the detector runs when the twin is on the bridge.
# Used by:  BRIDGED=1 ./run_live.sh
exec sudo -E bash "$(dirname "$0")/twin_net.sh" heal
