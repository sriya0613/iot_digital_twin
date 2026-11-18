#!/usr/bin/env bash
# run_protocol.sh — one full independent collection SESSION (the unit for held-out testing).
#
# A session = twin restored to clean baseline, fresh recorder on twin-mon, then a randomised
# sequence of episodes. Each session writes data/sessions/<SESSION_ID>.json (start/stop time,
# host load, tool versions, git commit, model hash, episode order); scripts/merge_sessions.py
# uses these files to give every window its session_id.
#
# Usage:  SESSION_ID=S07 SESSION_TAG="operator=sriya" ./scripts/run_protocol.sh
# Needs:  ./twin.sh restart, then 'IFACE=twin-mon ./record.sh' running in another terminal.
# Length: about 45 min (see scripts/COLLECTION_PROTOCOL.md).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
C="$HERE/scripts/collect_session.sh"
KIT="python3 -I $HERE/scripts/kit.py"
: "${SESSION_ID:?set SESSION_ID=S01..S99 (pre-registered in data/session_split.json)}"
export SESSION_ID SESSION_TAG="${SESSION_TAG:-}"

# Per-session order is shuffled (seeded by the session id) so attack order is not confounded with time.
EPISODES=(scan scan-slow bruteforce dos beacon beacon-long)
mapfile -t ORDER < <(printf '%s\n' "${EPISODES[@]}" | shuf --random-source=<(yes "$SESSION_ID"))

$KIT session-start --id "$SESSION_ID" --tag "$SESSION_TAG" --operator "${OPERATOR:-}" \
     --order "$(IFS=,; echo "${ORDER[*]}")"
STATUS=aborted
trap '$KIT session-stop --id "$SESSION_ID" --status "$STATUS" >/dev/null || true' EXIT

"$C" benign-idle
"$C" benign-http
"$C" benign-ping
"$C" benign-burst
for e in "${ORDER[@]}"; do
  "$C" "$e"
  "$C" benign-http        # benign between attacks: gives FPR data right after attacks too
done
"$C" heal                 # labelled 'healing' - excluded from classifier evaluation
STATUS=complete
echo "[protocol] session $SESSION_ID complete. Stop record.sh (Ctrl-C), then run scripts/build_dataset.sh"
