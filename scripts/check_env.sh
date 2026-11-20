#!/usr/bin/env bash
# check_env.sh — READ-ONLY readiness check for the live digital twin (Phases 3 and 4).
#
#   bash scripts/check_env.sh            # human-readable PASS / WARN / FAIL / SKIP lines
#   bash scripts/check_env.sh --json     # same checks, one JSON object (for the readiness report)
#
# It changes NOTHING: no interface, bridge, flow, namespace, file or process is created,
# modified or stopped, and no packet is sent to the twin except one ping and one HTTP HEAD
# when the twin is already up. Checks that need root use `sudo -n` (never prompts); without
# passwordless sudo they are reported as SKIP. Run it on the twin host, from the repo root.
#
# Exit code: 0 = no FAIL, 1 = at least one FAIL.
set -u
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
IID="${IID:-1}"
BR="${BR:-br-twin}"
DEV_IP="${DEV_IP:-192.168.0.1}"
DEV_MAC="${DEV_MAC:-00:de:fa:1a:01:00}"
CAPTURE_IFACE="${CAPTURE_IFACE:-twin-mon}"
RYU_URL="${RYU_URL:-http://127.0.0.1:8080}"
RYU_VENV="${RYU_VENV:-$HOME/ryu-venv}"
SCRATCH="$FIRMAE_DIR/scratch/$IID"
SYSCALL_LOG="${SYSCALL_LOG:-$SCRATCH/qemu.final.serial.log}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JSON=0; [ "${1:-}" = "--json" ] && JSON=1

NPASS=0; NWARN=0; NFAIL=0; NSKIP=0; ROWS=()
rec() {   # rec <PASS|WARN|FAIL|SKIP> <area> <check> <detail>
  case "$1" in PASS) NPASS=$((NPASS+1));; WARN) NWARN=$((NWARN+1));; FAIL) NFAIL=$((NFAIL+1));; SKIP) NSKIP=$((NSKIP+1));; esac
  if [ $JSON = 1 ]; then
    ROWS+=("$(python3 -c 'import json,sys; print(json.dumps(dict(zip(["status","area","check","detail"],sys.argv[1:]))))' "$1" "$2" "$3" "$4")")
  else
    printf "%-4s  %-10s %-34s %s\n" "$1" "$2" "$3" "$4"
  fi
}
have() { command -v "$1" >/dev/null 2>&1; }
SUDO=""; if [ "$(id -u)" = 0 ]; then SUDO=""; elif sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO="NONE"; fi
asroot() { [ "$SUDO" = NONE ] && return 99; $SUDO "$@"; }

# ---------------------------------------------------------------- host
. /etc/os-release 2>/dev/null; rec PASS host "os" "${PRETTY_NAME:-unknown} / $(uname -r)"
PY=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo none)
case "$PY" in 3.1[0-9]) rec PASS host "python3" "$PY";; none) rec FAIL host "python3" "not found";; *) rec WARN host "python3" "$PY (project built on 3.10)";; esac
CPUS=$(nproc); MEM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo)
rec "$([ "$CPUS" -ge 2 ] && echo PASS || echo WARN)" host "cpu / memory" "$CPUS cores, ${MEM} GiB"
FREE=$(df -Pk "$HERE" | awk 'NR==2{printf "%.1f", $4/1048576}')
rec "$(awk -v f="$FREE" 'BEGIN{print (f>=5)?"PASS":"WARN"}')" host "free disk (repo)" "${FREE} GiB (need >= 5 for logs + image copies)"
read L1 L5 L15 _ < /proc/loadavg; rec PASS host "load average" "$L1 $L5 $L15 (logged per session; energy features depend on it)"
[ "$SUDO" = NONE ] && rec WARN host "sudo" "no passwordless sudo: root-only checks are SKIP" || rec PASS host "sudo" "${SUDO:-root}"

# ---------------------------------------------------------------- repo
if git -C "$HERE" rev-parse HEAD >/dev/null 2>&1; then
  rec PASS repo "commit" "$(git -C "$HERE" rev-parse --short HEAD) on $(git -C "$HERE" rev-parse --abbrev-ref HEAD)"
  DIRTY=$(git -C "$HERE" status --porcelain --untracked-files=no | wc -l)
  rec "$([ "$DIRTY" = 0 ] && echo PASS || echo WARN)" repo "tracked files unchanged" "$DIRTY modified tracked file(s)"
else rec WARN repo "git" "not a git checkout - commit cannot be recorded per session"; fi
for f in record.sh stream/run.py stream/label_run.py scripts/collect_session.sh scripts/run_protocol.sh models_v3_hybrid/config.json; do
  [ -e "$HERE/$f" ] && rec PASS repo "$f" "present" || rec FAIL repo "$f" "missing"
done
if [ -f "$HERE/models_v3_hybrid/xgboost.json" ]; then rec PASS repo "model hash" "$(sha256sum "$HERE/models_v3_hybrid/xgboost.json" | cut -c1-16)"; fi

# ---------------------------------------------------------------- FirmAE / QEMU
[ -d "$FIRMAE_DIR" ] && rec PASS firmae "FIRMAE_DIR" "$FIRMAE_DIR" || rec FAIL firmae "FIRMAE_DIR" "$FIRMAE_DIR not found (set FIRMAE_DIR)"
[ -f "$FIRMAE_DIR/restore.sh" ] && rec PASS firmae "restore.sh" "present" || rec FAIL firmae "restore.sh" "missing: heal cannot run"
for img in image.raw image.baseline.raw; do
  if [ -f "$SCRATCH/$img" ]; then rec PASS firmae "$img" "$(du -h "$SCRATCH/$img" | cut -f1)"
  else rec FAIL firmae "$img" "missing in $SCRATCH"; fi
done
if [ -f "$FIRMAE_DIR/restore.sh" ]; then
  ORDER=$(grep -n -E 'cp |rsync|dd |qemu|run\.sh' "$FIRMAE_DIR/restore.sh" | head -6 | tr '\n' ' ')
  rec PASS firmae "restore.sh copy/boot lines" "${ORDER:-none found} (needed for the disk-hash heal check)"
fi
QPID=$(pgrep -f 'qemu-system-' | head -1)
if [ -n "$QPID" ]; then
  rec PASS qemu "emulator running" "pid $QPID, $(ps -o comm= -p "$QPID"), up $(ps -o etimes= -p "$QPID" | tr -d ' ') s"
else rec WARN qemu "emulator running" "not running (start with: sudo bash network/twin_net.sh up)"; fi
QBIN=$(ls /usr/bin/qemu-system-* /usr/local/bin/qemu-system-* 2>/dev/null | xargs -n1 basename 2>/dev/null | sort -u | tr '\n' ' ')
[ -n "$QBIN" ] && rec PASS qemu "qemu binaries" "$QBIN" || rec FAIL qemu "qemu binaries" "none found"

# ---------------------------------------------------------------- OVS / Ryu
if have ovs-vsctl; then
  rec PASS ovs "ovs-vsctl" "$(ovs-vsctl --version 2>/dev/null | head -1)"
  if asroot ovs-vsctl br-exists "$BR" 2>/dev/null; then
    rec PASS ovs "bridge $BR" "exists"
    rec PASS ovs "datapath_id" "$(asroot ovs-vsctl get bridge "$BR" datapath_id 2>/dev/null | tr -d '"')"
    FM=$(asroot ovs-vsctl get bridge "$BR" fail_mode 2>/dev/null)
    rec "$([ "$FM" = standalone ] && echo PASS || echo WARN)" ovs "fail_mode" "${FM:-unset} (standalone = fail-open; tested in EXP-12d)"
    MIR=$(asroot ovs-vsctl --columns=name,select_all list mirror 2>/dev/null | tr -s ' ' | tr '\n' ' ')
    [ -n "$MIR" ] && rec PASS ovs "mirror" "$MIR" || rec FAIL ovs "mirror" "no mirror on $BR - monitors would see nothing"
    PORTS=$(asroot ovs-vsctl list-ports "$BR" 2>/dev/null | tr '\n' ' ')
    for p in twin-mon twin-host v-atk v-cli "tap${IID}_0"; do
      case " $PORTS " in *" $p "*) rec PASS ovs "port $p" "on $BR";; *) rec "$([ "$p" = "tap${IID}_0" ] && echo WARN || echo FAIL)" ovs "port $p" "not on $BR";; esac
    done
    MF=$(asroot ovs-ofctl -O OpenFlow13 meter-features "$BR" 2>&1 | tr -s ' ' | tr '\n' ' ' | cut -c1-120)
    case "$MF" in *max_meter:0*|*"max_meters:0"*|*rror*|"") rec WARN ovs "meter support" "${MF:-no answer} (rate-limit may be unsupported)";; *) rec PASS ovs "meter support" "$MF";; esac
  else
    [ "$SUDO" = NONE ] && rec SKIP ovs "bridge $BR" "needs sudo" || rec FAIL ovs "bridge $BR" "does not exist (sudo bash network/twin_net.sh setup)"
  fi
else rec FAIL ovs "ovs-vsctl" "Open vSwitch not installed"; fi
if curl --noproxy "*" -s -m 2 "$RYU_URL/stats/switches" >/dev/null 2>&1; then
  rec PASS ryu "REST API" "$RYU_URL answers: switches $(curl --noproxy "*" -s -m 2 "$RYU_URL/stats/switches")"
else rec WARN ryu "REST API" "$RYU_URL not answering (Ryu down: containment rules cannot be added)"; fi
if [ -x "$RYU_VENV/bin/ryu-manager" ]; then
  rec PASS ryu "venv" "$("$RYU_VENV/bin/python" -c 'import ryu,eventlet; print("ryu", ryu.__version__ if hasattr(ryu,"__version__") else "?", "eventlet", eventlet.__version__)' 2>/dev/null)"
else rec WARN ryu "venv" "$RYU_VENV/bin/ryu-manager not found (set RYU_VENV)"; fi

# ---------------------------------------------------------------- namespaces / isolation
for ns in atk:192.168.0.10 cli:192.168.0.20; do
  n=${ns%%:*}; ip=${ns##*:}
  if ip netns list 2>/dev/null | grep -qw "$n"; then
    A=$(asroot ip -n "$n" -4 addr show 2>/dev/null | grep -o "inet [0-9.]*" | grep -v "inet 127\." | head -1)   # skip loopback
    if [ $? = 99 ] || [ "$SUDO" = NONE ]; then rec SKIP netns "$n address" "needs sudo"
    else [ "$A" = "inet $ip" ] && rec PASS netns "$n address" "$ip" || rec FAIL netns "$n address" "got '${A:-none}', want $ip"; fi
  else rec FAIL netns "$n" "namespace missing"; fi
done
if [ "$SUDO" != NONE ] && ip netns list 2>/dev/null | grep -qw atk; then
  DR=$(asroot ip -n atk route show default 2>/dev/null)
  [ -z "$DR" ] && rec PASS safety "atk default route" "none (attack traffic cannot leave the bridge)" || rec FAIL safety "atk default route" "$DR - remove before any attack"
  if asroot ip -n atk route get 1.1.1.1 >/dev/null 2>&1; then rec FAIL safety "atk internet route" "atk can route to 1.1.1.1"
  else rec PASS safety "atk internet route" "unreachable (checked with route lookup, no packet sent)"; fi
else rec SKIP safety "atk routing" "needs sudo and namespace atk"; fi
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
rec "$([ "$FWD" = 0 ] && echo PASS || echo WARN)" safety "host ip_forward" "$FWD (1 is acceptable only because atk has no route out)"

# ---------------------------------------------------------------- twin reachability
if ping -c1 -W2 "$DEV_IP" >/dev/null 2>&1; then
  rec PASS twin "ping $DEV_IP" "answers"
  # only ask for HTTP when the twin answered ping: a proxy or captive network can otherwise answer
  # in the twin's place and give a status code that did not come from the twin
  HC=$(curl --noproxy "*" -s -o /dev/null -m 10 -w '%{http_code}' "http://$DEV_IP/" 2>/dev/null)
  rec "$([ -n "$HC" ] && [ "$HC" != 000 ] && echo PASS || echo WARN)" twin "HTTP GET /" "status ${HC:-none} (record this code: heal check factor 3 uses it)"
else
  rec WARN twin "ping $DEV_IP" "no answer (twin down?)"
  rec SKIP twin "HTTP GET /" "twin not answering ping"
fi
ARP=$(ip neigh show "$DEV_IP" 2>/dev/null | grep -o 'lladdr [0-9a-f:]*' | cut -d' ' -f2)
[ -z "$ARP" ] && rec WARN twin "twin MAC" "not in ARP cache yet" || { [ "$ARP" = "$DEV_MAC" ] && rec PASS twin "twin MAC" "$ARP" || rec FAIL twin "twin MAC" "$ARP != $DEV_MAC (containment.py DEVICE_MACS)"; }

# ---------------------------------------------------------------- monitors
if ip link show "$CAPTURE_IFACE" 2>/dev/null | grep -q '[<,]UP[,>]'; then rec PASS monitor "capture iface" "$CAPTURE_IFACE up (training data was captured here)"
else rec FAIL monitor "capture iface" "$CAPTURE_IFACE not up"; fi
if [ -f "$SYSCALL_LOG" ]; then
  S1=$(stat -c %s "$SYSCALL_LOG"); sleep 3; S2=$(stat -c %s "$SYSCALL_LOG")
  rec "$([ "$S2" -gt "$S1" ] && echo PASS || echo WARN)" monitor "syscall log" "$SYSCALL_LOG grew $((S2-S1)) bytes in 3 s"
else rec FAIL monitor "syscall log" "$SYSCALL_LOG missing: syscall features would be constant"; fi
python3 -c 'import psutil' 2>/dev/null && rec PASS monitor "psutil (energy)" "importable" || rec FAIL monitor "psutil (energy)" "pip install psutil"
RECP=$(pgrep -af 'run.py (record|stream)' | grep -o -- '--iface [^ ]*' | head -1)
[ -n "$RECP" ] && rec "$([ "$RECP" = "--iface $CAPTURE_IFACE" ] && echo PASS || echo FAIL)" monitor "running recorder" "$RECP" || rec PASS monitor "running recorder" "none running (fine for this check)"

# ---------------------------------------------------------------- tools
for t in nmap hping3 curl tmux tcpdump sqlite3 shuf; do have $t && rec PASS tools "$t" "$(command -v $t)" || rec FAIL tools "$t" "missing (sudo apt install $t)"; done
for m in numpy sklearn xgboost joblib shap jsonschema pytest; do
  python3 -c "import $m" 2>/dev/null && rec PASS python "$m" "importable" || rec "$([ $m = shap ] && echo WARN || echo FAIL)" python "$m" "not importable"
done
have docker && rec PASS tools "docker" "present (not used by this repo's run path)" || rec PASS tools "docker" "absent (not used by this repo's run path)"

# ---------------------------------------------------------------- summary
if [ $JSON = 1 ]; then
  printf '{"pass": %d, "warn": %d, "fail": %d, "skip": %d, "checks": [%s]}\n' $NPASS $NWARN $NFAIL $NSKIP "$(IFS=,; echo "${ROWS[*]}")"
else
  echo; echo "SUMMARY: $NPASS pass, $NWARN warn, $NFAIL fail, $NSKIP skip"
fi
[ $NFAIL = 0 ]
