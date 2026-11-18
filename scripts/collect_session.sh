#!/usr/bin/env bash
# collect_session.sh — run ONE labelled episode against the twin and record its label.
#
# This wraps the project's existing tools; it does not replace them:
#   record.sh               (terminal 1) captures raw 5-s windows from all three monitors
#   stream/label_run.py     (this script) runs the traffic and writes the time span to the manifest
#   stream/run.py build     (scripts/build_dataset.sh) joins raw windows with manifest labels
#
# Usage (terminal 2, while ./record.sh is running in terminal 1):
#   ./scripts/collect_session.sh benign-http
#   ./scripts/collect_session.sh benign-ping
#   ./scripts/collect_session.sh scan
#   ./scripts/collect_session.sh scan-slow
#   ./scripts/collect_session.sh bruteforce
#   ./scripts/collect_session.sh dos
#   ./scripts/collect_session.sh beacon
#   ./scripts/collect_session.sh heal
#
# Environment overrides: TWIN_IP (192.168.0.1), MANIFEST (data/run_manifest.jsonl),
#   SESSION_TAG (free text stored in the note, e.g. "S07 operator=tavishi").
#
# SAFETY: every scenario is a SIMULATED attack (nmap, hping3, curl loops) sent from the
# isolated 'atk' namespace to the emulated router on br-twin. No real malware is used.
# The atk namespace must have no default route to the internet (checked below).
set -euo pipefail

SCENARIO="${1:?usage: $0 <scenario>  (benign-http|benign-ping|scan|scan-slow|bruteforce|dos|beacon|heal)}"
TWIN_IP="${TWIN_IP:-192.168.0.1}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${MANIFEST:-$HERE/data/run_manifest.jsonl}"
TAG="${SESSION_TAG:-}"
LR="python3 $HERE/stream/label_run.py --manifest $MANIFEST"

# ---------- preflight ------------------------------------------------------------
fail() { echo "[preflight] FAIL: $*" >&2; exit 1; }
for c in python3 ip curl; do command -v "$c" >/dev/null || fail "missing command $c"; done
for ns in atk cli; do ip netns list | grep -qw "$ns" || fail "namespace '$ns' missing (run network/twin_net.sh up)"; done
ping -c1 -W2 "$TWIN_IP" >/dev/null 2>&1 || fail "twin $TWIN_IP not answering (./twin.sh status)"
pgrep -f "run.py record" >/dev/null || fail "recorder not running - start ./record.sh in another terminal first"
# isolation: the attack namespace must not be able to reach anything outside br-twin
if sudo ip netns exec atk ip route | grep -q '^default'; then
  fail "namespace atk has a default route - remove it so attack traffic cannot leave the bridge"
fi
case "$SCENARIO" in scan*) command -v nmap >/dev/null || fail "nmap missing";; dos) command -v hping3 >/dev/null || fail "hping3 missing";; esac
echo "[preflight] ok  scenario=$SCENARIO  manifest=$MANIFEST"

# ---------- scenarios (same commands as the Oct 16 session, plus scan-slow) ---------
# A short benign gap before each attack keeps attack windows from sharing a 5-s window
# with the previous episode.
gap() { echo "[collect] idle gap ${1}s"; sleep "$1"; }

case "$SCENARIO" in
  benign-http)
    $LR --label benign --note "benign-http $TAG" -- \
      sudo ip netns exec cli bash -c "for i in \$(seq 1 40); do curl -s http://$TWIN_IP/ >/dev/null; sleep 3; done" ;;
  benign-ping)
    $LR --label benign --note "benign-ping $TAG" -- sudo ip netns exec cli ping -c 60 "$TWIN_IP" ;;
  scan)
    gap 15
    $LR --label malware --attack-class scan --note "scan full-T4 $TAG" -- \
      sudo ip netns exec atk nmap -T4 -p 1-65535 "$TWIN_IP" ;;
  scan-slow)
    # lower-volume variant, so the test set is not only "huge" scans
    gap 15
    $LR --label malware --attack-class scan --note "scan slow-T2 top100 $TAG" -- \
      sudo ip netns exec atk nmap -T2 --top-ports 100 "$TWIN_IP" ;;
  bruteforce)
    gap 15
    $LR --label malware --attack-class bruteforce --note "bruteforce basic-auth $TAG" -- \
      sudo ip netns exec atk bash -c "for i in \$(seq 1 1500); do curl -s -m 0.3 -u admin:wrong\$i http://$TWIN_IP/ >/dev/null; done" ;;
  dos)
    gap 15
    $LR --label malware --attack-class dos --note "dos syn-flood 20s $TAG" -- \
      sudo ip netns exec atk timeout 20 hping3 -S --flood -p 80 "$TWIN_IP" || true ;;
  beacon)
    gap 15
    $LR --label malware --attack-class beacon --note "beacon 5s-period 60s $TAG" -- \
      sudo ip netns exec atk timeout 60 bash -c "while true; do curl -s -m 2 http://$TWIN_IP/ >/dev/null; sleep 5; done" || true ;;
  heal)
    $LR --label healing --pad 150 --note "heal $TAG" -- sudo bash "$HERE/network/twin_net.sh" heal ;;
  *) echo "unknown scenario $SCENARIO" >&2; exit 2 ;;
esac
echo "[collect] done: $SCENARIO  (last manifest line below)"
tail -n1 "$MANIFEST"
