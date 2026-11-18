#!/usr/bin/env bash
# collect_session.sh — run ONE labelled episode against the twin and record its label.
#
# This wraps the project's existing tools; it does not replace them:
#   record.sh               (terminal 1) captures raw 5-s windows from all three monitors.
#                           MUST capture on the mirror port:  IFACE=twin-mon ./record.sh
#                           (the Oct 16/19 training data were captured on twin-mon; record.sh's
#                           default tap1_0.1 is the pre-bridge capture point used on Oct 3)
#   stream/label_run.py     (this script) runs the traffic and writes the time span to the manifest
#   stream/run.py build     (scripts/build_dataset.sh) joins raw windows with manifest labels
#
# Usage (terminal 2, while IFACE=twin-mon ./record.sh is running in terminal 1):
#   ./scripts/collect_session.sh benign-http     # GET / every 3 s, 40 times
#   ./scripts/collect_session.sh benign-ping     # 60 pings
#   ./scripts/collect_session.sh benign-burst    # browser-like bursts: 10-20 quick GETs every 15-30 s, 2 min
#   ./scripts/collect_session.sh benign-idle     # no traffic from us for 120 s (device background only)
#   ./scripts/collect_session.sh scan            # nmap -T4 all ports
#   ./scripts/collect_session.sh scan-slow       # nmap -T2 top 100 ports
#   ./scripts/collect_session.sh bruteforce      # 1500 basic-auth GETs, 0.3 s timeout
#   ./scripts/collect_session.sh dos             # 20 s SYN flood
#   ./scripts/collect_session.sh beacon          # GET / every 5 s for 60 s (Oct 16 variant)
#   ./scripts/collect_session.sh beacon-long     # GET / every BEACON_PERIOD s (+-20% jitter) for 300 s
#   ./scripts/collect_session.sh heal            # labelled restore of the twin
#
# Environment: TWIN_IP (192.168.0.1), MANIFEST (data/run_manifest.jsonl), SESSION_ID (S01..),
#   SESSION_TAG (free text stored in the note), CAPTURE_IFACE (twin-mon),
#   BEACON_PERIOD (beacon-long; default from SESSION_ID via kit.py beacon-period, else 30),
#   TWIN_PAGES (benign-burst paths, default "/"),
#   BENIGN_BURST_SECONDS (120), BEACON_LONG_SECONDS (300), IDLE_SECONDS (120), HEAL_PAD (150),
#   HEAL_CMD (sudo bash network/twin_net.sh heal), BEACON_LOG: overridable for tests only.
#
# SAFETY: every scenario is a SIMULATED attack (nmap, hping3, curl loops) sent from the
# isolated 'atk' namespace to the emulated router on br-twin. No real malware is used.
# The atk namespace must have no default route to the internet (checked below).
set -euo pipefail

SCENARIO="${1:?usage: $0 <scenario>  (benign-http|benign-ping|benign-burst|benign-idle|scan|scan-slow|bruteforce|dos|beacon|beacon-long|heal)}"
TWIN_IP="${TWIN_IP:-192.168.0.1}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${MANIFEST:-$HERE/data/run_manifest.jsonl}"
CAPTURE_IFACE="${CAPTURE_IFACE:-twin-mon}"
SID="${SESSION_ID:-}"
TAG="${SID:+$SID }${SESSION_TAG:-}"
LR="python3 $HERE/stream/label_run.py --manifest $MANIFEST"
KIT="python3 -I $HERE/scripts/kit.py"

# ---------- preflight ------------------------------------------------------------
fail() { echo "[preflight] FAIL: $*" >&2; exit 1; }
for c in python3 ip curl; do command -v "$c" >/dev/null || fail "missing command $c"; done
for ns in atk cli; do ip netns list | grep -w "$ns" >/dev/null || fail "namespace '$ns' missing (run network/twin_net.sh up)"; done
ping -c1 -W2 "$TWIN_IP" >/dev/null 2>&1 || fail "twin $TWIN_IP not answering (./twin.sh status)"
REC_IFACE="$(pgrep -af 'run.py record' | $KIT recorder-iface)"
[ -n "$REC_IFACE" ] || fail "recorder not running - start 'IFACE=$CAPTURE_IFACE ./record.sh' in another terminal first"
[ "$REC_IFACE" = "$CAPTURE_IFACE" ] || fail "recorder captures on '$REC_IFACE', must be '$CAPTURE_IFACE' (restart it: IFACE=$CAPTURE_IFACE ./record.sh)"
# isolation: the attack namespace must not be able to reach anything outside br-twin
if sudo ip netns exec atk ip route | grep "^default" >/dev/null; then
  fail "namespace atk has a default route - remove it so attack traffic cannot leave the bridge"
fi
case "$SCENARIO" in scan*) command -v nmap >/dev/null || fail "nmap missing";; dos) command -v hping3 >/dev/null || fail "hping3 missing";; esac
echo "[preflight] ok  scenario=$SCENARIO  session=${SID:-none}  capture=$REC_IFACE  manifest=$MANIFEST"

# ---------- scenarios (Oct 16 commands kept unchanged; new ones marked v2) -----------
# A short idle gap before each attack keeps attack windows from sharing a 5-s window
# with the previous episode.
gap() { echo "[collect] idle gap ${1}s"; sleep "$1"; }

case "$SCENARIO" in
  benign-http)
    $LR --label benign --note "benign-http $TAG" -- \
      sudo ip netns exec cli bash -c "for i in \$(seq 1 40); do curl -s http://$TWIN_IP/ >/dev/null; sleep 3; done" ;;
  benign-ping)
    $LR --label benign --note "benign-ping $TAG" -- sudo ip netns exec cli ping -c 60 "$TWIN_IP" ;;
  benign-burst)   # v2: what a browser does when someone opens the web UI - the hard negative for bruteforce
    PAGES="${TWIN_PAGES:-/}"
    $LR --label benign --note "benign-burst v2 $TAG" -- \
      sudo ip netns exec cli bash -c "end=\$((SECONDS+${BENIGN_BURST_SECONDS:-120})); while [ \$SECONDS -lt \$end ]; do
          n=\$((10 + RANDOM % 11)); for i in \$(seq 1 \$n); do for p in $PAGES; do curl -s -m 2 http://$TWIN_IP\$p >/dev/null & done; done; wait
          sleep \$((15 + RANDOM % 16)); done" ;;
  benign-idle)    # v2: no traffic from us; only what the device and bridge do on their own
    $LR --label benign --note "benign-idle v2 $TAG" --seconds "${IDLE_SECONDS:-120}" ;;
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
  beacon-long)    # v2: realistic C2 periods with jitter, long enough to see the period across windows
    P="${BEACON_PERIOD:-}"
    [ -z "$P" ] && [ -n "$SID" ] && P="$($KIT beacon-period --id "$SID")"
    P="${P:-30}"
    LOG="${BEACON_LOG:-$HERE/data/beacon_requests.jsonl}"     # one line per request: lets later work check timing
    gap 15
    $LR --label malware --attack-class beacon --note "beacon-long v2 period=${P}s jitter=20% 300s $TAG" -- \
      sudo ip netns exec atk timeout ${BEACON_LONG_SECONDS:-300} bash -c "while true; do
          t=\$(date +%s.%N); curl -s -m 2 http://$TWIN_IP/ >/dev/null
          echo \"{\\\"t\\\": \$t, \\\"session\\\": \\\"${SID:-}\\\", \\\"period_s\\\": $P}\" >> '$LOG'
          sleep \$(awk -v p=$P -v r=\$RANDOM 'BEGIN{printf \"%.2f\", p*(0.8+0.4*r/32767)}'); done" || true ;;
  heal)
    # HEAL_CMD / HEAL_PAD exist so tests can run the protocol without restoring a real twin
    $LR --label healing --pad "${HEAL_PAD:-150}" --note "heal $TAG" -- ${HEAL_CMD:-sudo bash "$HERE/network/twin_net.sh" heal} ;;
  *) echo "unknown scenario $SCENARIO" >&2; exit 2 ;;
esac
echo "[collect] done: $SCENARIO  (last manifest line below)"
tail -n1 "$MANIFEST"
