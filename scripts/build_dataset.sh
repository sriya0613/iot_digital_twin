#!/usr/bin/env bash
# build_dataset.sh — join raw windows with the manifest into one labelled dataset, then validate.
#
#   ./scripts/build_dataset.sh data/dataset_v4.jsonl            # all raw sessions
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
if [ "$#" -eq 0 ]; then set -- "$HERE"/data/raw/session_*.jsonl; fi
( cd "$HERE/stream" && python3 run.py build --raw "$@" --manifest "$HERE/data/run_manifest.jsonl" \
      --scaler "$OUT.scaler.json" --out "$OUT" )
python3 -I "$HERE/scripts/validate_session.py" "$OUT"
