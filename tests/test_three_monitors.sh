#!/bin/bash
# tests/test_three_monitors.sh — end-to-end check of the three-monitor pipeline on
# one Linux machine, WITHOUT the twin. Takes about 3 minutes. Needs root to sniff:
#
#     sudo bash tests/test_three_monitors.sh
#
# A stand-in device (tests/sim_twin.py) plays the router: it serves a few ports on
# 127.0.0.1, writes Firmadyne-style kernel lines to a log and uses some CPU. The
# test then does exactly what you do on the real twin:
#   record (network + syscall + energy) -> label -> build -> train -> live detect -> heal
set -u
cd "$(dirname "$0")/.."
PY=${PY:-python3}
W=$(mktemp -d)
cleanup() { kill $TWIN 2>/dev/null; pkill -f "run.py (record|stream) --iface lo" 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL  $1"; exit 1; }
# The sniffer needs root, but training and the detector run as the normal user: that is
# how run_live.sh works, and the ML libraries are installed for that user, not for root.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  chown "$SUDO_USER" "$W"; chmod 755 "$W"
  urun() { sudo -H -u "$SUDO_USER" env "PATH=$PATH" "$@"; }
else
  urun() { env "$@"; }
fi
urun $PY -c "import sklearn, xgboost, numpy, joblib" 2>/dev/null || fail "the detector's libraries are missing for user ${SUDO_USER:-$(id -un)}: run  pip3 install -r requirements.txt  (without sudo)"

$PY tests/sim_twin.py qemu-system-sim --log $W/serial.log > $W/twin.out 2>&1 &
TWIN=$!
sleep 1

echo "[1/5] recording 100 s with all three monitors (benign traffic, 6 labelled scans, idle)..."
( cd stream && $PY run.py record --iface lo --syscall-log $W/serial.log --duration 100 --out $W/raw.jsonl > $W/rec.out 2>&1 ) &
REC=$!
sleep 3
$PY stream/label_run.py --label benign --manifest $W/manifest.jsonl --seconds 25 > /dev/null &
$PY tests/sim_traffic.py benign --seconds 25
sleep 6
for i in 1 2 3 4 5 6; do
  $PY stream/label_run.py --label malware --manifest $W/manifest.jsonl --note "connect scan" -- \
      $PY tests/sim_traffic.py scan --ports $((300 + i * 150)) > /dev/null
  sleep 7
done
wait $REC
grep -q "syscall monitor: [1-9]" $W/rec.out || fail "syscall monitor recorded no events"
grep -q "samples, [1-9][0-9]* with emulator" $W/rec.out || fail "energy monitor never saw the emulator process"
echo "PASS  recorded $(wc -l < $W/raw.jsonl) windows; $(grep 'syscall monitor' $W/rec.out | cut -c5-); $(grep 'energy monitor' $W/rec.out | cut -c5-)"

echo "[2/5] building the dataset and scaler..."
( cd stream && $PY run.py build --raw $W/raw.jsonl --manifest $W/manifest.jsonl --out $W/dataset_v2.jsonl --scaler $W/scaler_v2.json 2> $W/build.out ) || fail "build"
grep "label breakdown" $W/build.out
grep -q "'malware': [4-9]" $W/build.out || fail "fewer than 4 windows labelled malware"
echo "PASS  dataset built"

echo "[3/5] training on the 45-feature dataset..."
urun $PY train_detector.py --dataset $W/dataset_v2.jsonl --model-dir $W/models_v2 --report-dir $W/reports_v2 --no-plots > $W/train.out 2>&1 || { cat $W/train.out; fail "training"; }
grep -E "schema 2.0.0|label mode|k-fold|[0-9]-fold over|SHAP share" $W/train.out
echo "PASS  model trained"

echo "[4/5] live: stream -> detector -> stand-in restore (45 s)..."
( cd stream && $PY run.py stream --iface lo --scaler $W/scaler_v2.json --syscall-log $W/serial.log --duration 45 --out - 2> $W/stream.err ) \
  | urun FAKE_RESTORE_LOG=$W/restore.log $PY live_detector.py --model-dir $W/models_v2 \
      --restore-cmd "$PY tests/fake_restore.py" --grace 5 --events $W/events.jsonl > $W/det.out 2>&1 &
DET=$!
sleep 8;  $PY tests/sim_traffic.py benign --seconds 8
sleep 4;  $PY tests/sim_traffic.py scan --ports 700
wait $DET
grep -E "MALICIOUS|HEALED|stopped" $W/det.out
[ "$(wc -l < $W/restore.log 2>/dev/null || echo 0)" = "1" ] || { cat $W/det.out; fail "expected exactly one restore"; }
echo "PASS  scan detected live and one restore fired"

echo "[5/5] every record validates against the v2 schema..."
$PY - <<PYEOF || fail "schema validation"
import json
try:
    import jsonschema
except ImportError:
    print("      (jsonschema not installed - skipped)"); raise SystemExit(0)
S = json.load(open("contracts/fingerprint.schema.v2.json"))
n = 0
for line in open("$W/dataset_v2.jsonl"):
    jsonschema.validate(json.loads(line), S); n += 1
print("      %d records valid" % n)
PYEOF
echo "PASS  schema"
echo
echo "ALL THREE-MONITOR TESTS PASSED   (working files in $W)"
