#!/usr/bin/env bash
# build_dataset.sh — join raw windows with the manifest into one labelled dataset, then validate.
#
#   ./scripts/build_dataset.sh data/dataset_v4.jsonl            # all raw sessions captured on twin-mon
#   ./scripts/build_dataset.sh data/dataset_v4.jsonl data/raw/session_2026111*.jsonl
#
# NOTE on scaling: `stream/run.py build` always refits the min-max scaler on the raw files it
# is given. So build ONE dataset from ALL raw sessions in one pass (old + new) so every window
# is on the same scale. Known limitation: min/max bounds then include test sessions. Min-max
# bounds are a weak leak (two numbers per feature, no labels), but it is listed in the paper's
# threats-to-validity section; the fix would be a per-split rescale from raw values.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: $0 <out.jsonl> [raw session files...]}"; shift
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"     # absolute: the build runs inside stream/
if [ "$#" -eq 0 ]; then set -- "$HERE"/data/raw/session_*.jsonl; fi
# Keep only non-empty raw files captured on CAPTURE_IFACE (default twin-mon) - this excludes the Oct 3
# sessions (captured on tap1_0.1) and the empty file record.sh leaves when it is stopped. Paths become
# absolute (pilot S00: relative paths broke once the build changed into stream/).
RAW="$(python3 -I "$HERE/scripts/kit.py" raw-files --iface "${CAPTURE_IFACE:-twin-mon}" "$@")" || exit 1
mapfile -t RAWS <<< "$RAW"
echo "[build] ${#RAWS[@]} raw file(s) captured on ${CAPTURE_IFACE:-twin-mon}"
( cd "$HERE/stream" && python3 run.py build --raw "${RAWS[@]}" --manifest "$HERE/data/run_manifest.jsonl" \
      --scaler "$OUT.scaler.json" --out "$OUT" )
python3 -I "$HERE/scripts/validate_session.py" "$OUT"
