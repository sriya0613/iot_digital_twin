#!/usr/bin/env bash
# run_protocol.sh — one full independent collection SESSION (the unit for held-out testing).
#
# A session = twin restored to clean baseline, fresh recorder file, then a fixed
# randomised sequence of episodes. Run on a different day / after a twin restart for each
# session so sessions are independent. Target for Phase 4: >= 15 sessions, which gives
# >= 3 independent episodes of every attack class in the final test sessions.
#
# Usage:  SESSION_TAG="S07 operator=sriya" ./scripts/run_protocol.sh
# Needs:  ./record.sh running in another terminal (started AFTER ./twin.sh restart).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
C="$HERE/scripts/collect_session.sh"
export SESSION_TAG="${SESSION_TAG:-S?}"

# Per-session order is shuffled (seeded by the tag) so attack order is not confounded with time.
EPISODES=(scan scan-slow bruteforce dos beacon)
mapfile -t ORDER < <(printf '%s\n' "${EPISODES[@]}" | shuf --random-source=<(yes "$SESSION_TAG"))

"$C" benign-http
"$C" benign-ping
for e in "${ORDER[@]}"; do
  "$C" "$e"
  "$C" benign-http        # benign between attacks: gives FPR data right after attacks too
done
"$C" heal                 # labelled 'healing' - excluded from classifier evaluation
echo "[protocol] session $SESSION_TAG complete. Stop record.sh (Ctrl-C), then run scripts/build_dataset.sh"
