#!/bin/bash
# network/twin_net.sh — Person A: put the twin on an Open vSwitch bridge, with a
# mirror port for the monitors, two test hosts, and a Ryu controller hook.
#
#   sudo bash network/twin_net.sh up         start EVERYTHING in the background (bridge, Ryu, twin, watchdog)
#   sudo bash network/twin_net.sh down       stop watchdog, twin and Ryu
#   sudo bash network/twin_net.sh setup      build the bridge once (twin running the old way)
#   sudo bash network/twin_net.sh start      boot the twin from the clean baseline, detached, on the bridge
#   sudo bash network/twin_net.sh heal       same as start; this is what the detector calls on an attack
#   sudo bash network/twin_net.sh attach     move an already running twin onto the bridge
#        bash network/twin_net.sh status     check every link in the chain (--json for the dashboard)
#   sudo bash network/twin_net.sh watchdog   keep checking the twin is alive; heal it if it dies
#   sudo bash network/twin_net.sh console [twin|ryu|watchdog]   look at a background window (leave: Ctrl-b then d)
#   sudo bash network/twin_net.sh clean      clear stale tap interfaces and loop mounts (twin stopped)
#   sudo bash network/twin_net.sh teardown   remove the bridge and go back to the old wiring
#
# Layout (all on the host):
#
#   twin (QEMU) --tapN_0--+                       +-- twin-host  192.168.0.2  (this host: restore.sh, browser, scans)
#                         |      br-twin (OVS)    +-- v-atk  --> netns atk 192.168.0.10  02:00:00:00:00:10
#        Ryu controller --+   OpenFlow 1.3        +-- v-cli  --> netns cli 192.168.0.20  02:00:00:00:00:20
#                         |                       +-- twin-mon (mirror of every packet; the monitors sniff here)
#
# The firmware tags its LAN frames with a VLAN (FirmAE makes tapN_0.<vid> for it), so the
# twin's tap is a trunk for that VLAN and every other port is an access port on it.
set -u
FIRMAE_DIR="${FIRMAE_DIR:-/home/vboxuser/firmae/FirmAE}"
IID="${IID:-1}"
BR="${BR:-br-twin}"
SCRATCH="${SCRATCH:-${FIRMAE_DIR}/scratch/${IID}}"
TAP="tap${IID}_0"
DEV_IP="${DEV_IP:-192.168.0.1}"
HOST_IP="${HOST_IP:-192.168.0.2}"
CTRL="${CTRL:-tcp:127.0.0.1:6653}"
REAL_RESTORE="${REAL_RESTORE:-$FIRMAE_DIR/restore.sh}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
STATE="$HERE/.state"

[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
mkdir -p "$STATE"
say() { echo "[twin_net] $*"; }
die() { echo "[twin_net] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 not installed - run: sudo apt install $2"; }
no_v6() { [ -e "/proc/sys/net/ipv6/conf/$1/disable_ipv6" ] && echo 1 > "/proc/sys/net/ipv6/conf/$1/disable_ipv6"; true; }
qemu_up() { pgrep -f 'qemu-system-' >/dev/null; }

vlan() {   # VLAN id of the firmware's LAN frames; 0 = untagged
  local v; v=$(ls /sys/class/net | sed -n "s/^${TAP}\.\([0-9]*\)$/\1/p" | head -1)
  if [ -n "$v" ]; then echo "$v" > "$STATE/vlan"; echo "$v"; return; fi
  if [ -f "$STATE/vlan" ]; then cat "$STATE/vlan"; return; fi
  [ -n "${VLAN:-}" ] && { echo "$VLAN"; return; }
  die "cannot tell which VLAN the firmware uses: start the twin the usual way first (so $TAP.<vid> exists), or pass VLAN=0 for untagged"
}

access() { local vid; vid=$(vlan); [ "$vid" = 0 ] || ovs-vsctl set port "$1" tag="$vid"; }

add_host() {   # add_host <name> <ip> <mac> : a network namespace wired to the bridge
  local n=$1 ip=$2 mac=$3
  ip netns list | grep -qw "$n" || ip netns add "$n"
  if ! ip link show "v-$n" >/dev/null 2>&1; then
    ip link add "v-$n" type veth peer name "e-$n"
    ip link set "e-$n" netns "$n"
  fi
  ip -n "$n" link set "e-$n" address "$mac"
  ip -n "$n" addr replace "$ip/24" dev "e-$n"
  ip -n "$n" link set lo up; ip -n "$n" link set "e-$n" up
  ip netns exec "$n" sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null
  no_v6 "v-$n"; ip link set "v-$n" up
  ovs-vsctl --may-exist add-port "$BR" "v-$n"; access "v-$n"
}

setup() {
  need ovs-vsctl openvswitch-switch; need tmux tmux; need tcpdump tcpdump
  local vid; vid=$(vlan)
  say "firmware LAN VLAN: $vid"
  ovs-vsctl --may-exist add-br "$BR"
  # secure, not standalone: in standalone OVS deletes all flows ~12 s after losing Ryu and falls back
  # to normal switching, silently ending any quarantine (E11, 2026-11-26). secure keeps the installed
  # flows (quarantine + Ryu's priority-0 NORMAL rule) while Ryu is down; with no Ryu at all, nothing flows.
  ovs-vsctl set bridge "$BR" protocols=OpenFlow13 fail_mode=secure
  ovs-vsctl set-controller "$BR" "$CTRL"
  # twin-host takes over 192.168.0.2 from tapN_0.<vid>
  ovs-vsctl --may-exist add-port "$BR" twin-host -- set interface twin-host type=internal
  access twin-host; no_v6 twin-host; ip link set twin-host up
  # mirror: a copy of every packet on the bridge goes to twin-mon
  ovs-vsctl --may-exist add-port "$BR" twin-mon -- set interface twin-mon type=internal
  no_v6 twin-mon; ip link set twin-mon up
  ovs-vsctl clear bridge "$BR" mirrors
  ovs-vsctl -- --id=@p get port twin-mon \
            -- --id=@m create mirror name=twin-mirror select-all=true output-port=@p \
            -- set bridge "$BR" mirrors=@m >/dev/null
  add_host atk 192.168.0.10 02:00:00:00:00:10      # attacker
  add_host cli 192.168.0.20 02:00:00:00:00:20      # normal client
  if qemu_up && ip link show "$TAP" >/dev/null 2>&1; then attach; else
    ip addr replace "$HOST_IP/24" dev twin-host; say "twin not running - it is attached on the next start"; fi
  say "bridge ready. Check with: bash network/twin_net.sh status"
}

attach() {
  local vid; vid=$(vlan)
  ovs-vsctl br-exists "$BR" || die "no bridge - run setup first"
  ip link show "$TAP" >/dev/null 2>&1 || die "$TAP does not exist - is the twin running?"
  ovs-vsctl --may-exist add-port "$BR" "$TAP"
  if [ "$vid" = 0 ]; then ovs-vsctl clear port "$TAP" trunks; else ovs-vsctl set port "$TAP" trunks="$vid"; fi
  if ip link show "$TAP.$vid" >/dev/null 2>&1; then
    # twin-host takes over the old interface's MAC as well as its 192.168.0.2: the firmware
    # keeps the host's MAC in its ARP cache and does not update it, so a new MAC = no replies.
    ip link set twin-host address "$(cat /sys/class/net/$TAP.$vid/address)"
    ip link delete "$TAP.$vid"
  fi
  ip addr replace "$HOST_IP/24" dev twin-host
  ip neigh flush dev twin-host 2>/dev/null || true   # drop any stale ARP so the twin re-resolves after a boot/heal
  no_v6 "$TAP"
  [ "${1:-}" = quiet ] || say "twin ($TAP) is on $BR"
}

clean_taps() {   # leftovers of an emulator that died without cleaning up ("RTNETLINK answers: File exists")
  qemu_up && return
  for l in $(ls /sys/class/net | grep -E "^${TAP}(\.[0-9]+)?$" | sort -r); do ip link delete "$l" 2>/dev/null && say "removed stale $l"; done
}

clean_loops() {   # stale loop mounts of the disk image block restore.sh ("Text file busy" / "already mounted")
  qemu_up && return
  local img="$SCRATCH/image"
  mountpoint -q "$img" && { umount "$img" 2>/dev/null || umount -l "$img" 2>/dev/null; say "unmounted stale $img"; }
  for d in $(losetup -a 2>/dev/null | grep "$SCRATCH/image" | cut -d: -f1); do
    kpartx -d "$d" 2>/dev/null; losetup -d "$d" 2>/dev/null && say "detached stale loop $d"
  done
}

heal() {   # restore from the clean baseline; retry once if the firmware fails to boot (FirmAE is flaky)
  [ -f "$REAL_RESTORE" ] || die "restore script not found: $REAL_RESTORE"
  ovs-vsctl br-exists "$BR" || die "no bridge - run setup first"
  local other; other=$(cat "$STATE/healing" 2>/dev/null)
  if [ -n "$other" ] && kill -0 "$other" 2>/dev/null; then
    say "a heal is already running (pid $other) - waiting for it"
    while kill -0 "$other" 2>/dev/null; do sleep 2; done
    if ping -c 3 -W 2 "$DEV_IP" >/dev/null 2>&1; then say "twin is back"; exit 0; else say "twin still not answering"; exit 3; fi
  fi
  echo $$ > "$STATE/healing"; trap 'rm -f "$STATE/healing"' EXIT

  local tries="${HEAL_TRIES:-2}" n=0 T0=$(date +%s)
  while [ "$n" -lt "$tries" ]; do
    n=$((n+1))
    [ "$n" -gt 1 ] && say "heal attempt $n of $tries (previous boot did not come up)"
    rm -f "$STATE/restore.rc"; local t0=$(date +%s)
    tmux kill-session -t twin 2>/dev/null && sleep 2
    pkill -f 'qemu-system-' 2>/dev/null && sleep 3
    clean_taps
    # clear stale loop mounts/devices so restore.sh can overwrite image.raw (else it exits 1)
    local SCR="$FIRMAE_DIR/scratch/$IID"
    umount "$SCR/image" 2>/dev/null || true
    for L in $(losetup -j "$SCR/image.raw" 2>/dev/null | cut -d: -f1) \
             $(losetup -nO NAME 2>/dev/null | while read d; do losetup -nO BACK-FILE "$d" 2>/dev/null | grep -q "$SCR/image" && echo "$d"; done); do
      kpartx -d "$L" 2>/dev/null || true
      losetup -d "$L" 2>/dev/null && say "cleared stale loop $L"
    done
    rm -f /tmp/firmae_restore.log
    tmux new-session -d -s twin "bash '$REAL_RESTORE'; echo \$? > '$STATE/restore.rc'; echo; echo '[twin] restore.sh finished. The emulator runs in this window - detach with Ctrl-b d, type nothing else.'; exec sleep infinity"
    say "restoring in tmux session 'twin' (attempt $n; watch: sudo tmux attach -t twin)"
    while [ ! -f "$STATE/restore.rc" ]; do
      if qemu_up && ip link show "$TAP" >/dev/null 2>&1; then attach quiet 2>/dev/null; fi
      sleep 1
      [ $(( $(date +%s) - t0 )) -gt "${HEAL_TIMEOUT:-300}" ] && { say "restore attempt $n did not finish in ${HEAL_TIMEOUT:-300} s"; break; }
    done
    local RC; RC=$(cat "$STATE/restore.rc" 2>/dev/null || echo 2)
    qemu_up && attach quiet
    if ping -c 3 -W 2 "$DEV_IP" >/dev/null 2>&1; then
      say "healed: $DEV_IP answers through $BR after $(( $(date +%s) - T0 )) s (restore.sh exit $RC, attempt $n)"
      exit 0
    fi
    say "attempt $n: $DEV_IP does not answer yet"
  done
  say "twin did not come up after $tries attempts - see: sudo tmux attach -t twin"
  exit 3
}

rules_count() {   # flows above the default normal-switching rule (priority 0) = containment in force
  ovs-ofctl -O OpenFlow13 dump-flows "$BR" 2>/dev/null | grep -o 'priority=[0-9]*' | grep -vc 'priority=0$'
}

status() {
  [ "${1:-}" = "--json" ] && exec python3 "$HERE/watchdog.py" --status --json
  local ok=1 vid; vid=$(cat "$STATE/vlan" 2>/dev/null || echo "?")
  ck() { if eval "$2" >/dev/null 2>&1; then printf "  OK    %s\n" "$1"; else printf "  FAIL  %s\n" "$1"; ok=0; fi; }
  echo "bridge $BR (firmware VLAN $vid)"
  ck "bridge exists"                      "ovs-vsctl br-exists $BR"
  ck "emulator running"                   "pgrep -f qemu-system-"
  ck "$TAP is a port on the bridge"       "[ \"\$(ovs-vsctl port-to-br $TAP)\" = $BR ] && ip link show $TAP"
  ck "no old $TAP.$vid interface left"    "! ip link show $TAP.$vid"
  ck "host 192.168.0.2 on twin-host"      "ip -4 addr show twin-host | grep -q $HOST_IP"
  ck "host -> twin ping"                  "ping -c 2 -W 2 $DEV_IP"
  ck "attacker ns (atk) -> twin ping"     "ip netns exec atk ping -c 2 -W 2 $DEV_IP"
  ck "client ns (cli) -> twin ping"       "ip netns exec cli ping -c 2 -W 2 $DEV_IP"
  ck "mirror twin-mon sees twin traffic"  "( sleep 1; ping -c 3 -W 1 $DEV_IP ) & timeout 6 tcpdump -nn -i twin-mon -c 3 'icmp or (vlan and icmp)'"
  printf "  info  emulator detached in tmux 'twin': %s\n" "$(tmux has-session -t twin 2>/dev/null && echo yes || echo 'no (started the old way)')"
  printf "  info  Ryu controller connected: %s\n" "$(ovs-vsctl get controller $BR is_connected 2>/dev/null || echo no)"
  printf "  info  containment rules active on %s: %s\n" "$BR" "$(rules_count)"
  printf "  info  twin MAC: %s   datapath id: %s\n" "$(ip neigh show $DEV_IP dev twin-host | awk '{print $3}')" \
         "$(ovs-vsctl get bridge $BR datapath_id 2>/dev/null | tr -d '\"')"
  [ $ok = 1 ] && echo "ALL OK" || echo "SOME CHECKS FAILED"
}

up() {   # everything, in background tmux sessions: bridge, Ryu, twin, watchdog
  setup
  if ! tmux has-session -t ryu 2>/dev/null; then
    local RYU="${RYU_MANAGER:-/home/${SUDO_USER:-vboxuser}/ryu-venv/bin/ryu-manager}"
    [ -x "$RYU" ] || die "ryu-manager not found at $RYU (set RYU_MANAGER=...)"
    tmux new-session -d -s ryu "cd '$ROOT' && '$RYU' --wsapi-host 127.0.0.1 ryu.app.ofctl_rest network/ryu_base.py 2>&1 | tee '$STATE/ryu.log'"
    say "Ryu started in tmux session 'ryu'"
  fi
  local i; for i in $(seq 1 20); do
    [ "$(ovs-vsctl get controller "$BR" is_connected 2>/dev/null)" = true ] && break; sleep 1; done
  [ "$(ovs-vsctl get controller "$BR" is_connected 2>/dev/null)" = true ] && say "Ryu connected" \
    || say "WARNING: Ryu not connected after 20 s - see $STATE/ryu.log (fail_mode secure: NO traffic flows until Ryu connects)"
  if qemu_up && [ "$(ovs-vsctl port-to-br "$TAP" 2>/dev/null)" = "$BR" ] && ping -c 2 -W 2 "$DEV_IP" >/dev/null 2>&1; then
    say "twin already up on $BR - not restarting it"
  else
    ( heal ) || die "twin did not come up - see: sudo tmux attach -t twin"
  fi
  if [ "${NOWATCHDOG:-0}" = 1 ]; then
    say "watchdog NOT started (NOWATCHDOG=1) - healing is owned by whatever you run next"
  elif ! tmux has-session -t watchdog 2>/dev/null; then
    tmux new-session -d -s watchdog "python3 '$HERE/watchdog.py' 2>&1 | tee -a '$STATE/watchdog.log'"
    say "watchdog started in tmux session 'watchdog'"
  fi
  status
}

down() {   # stop watchdog, twin and Ryu (the bridge stays; 'up' brings it all back)
  tmux kill-session -t watchdog 2>/dev/null && say "watchdog stopped"
  tmux kill-session -t twin 2>/dev/null; pkill -f 'qemu-system-' 2>/dev/null && say "twin stopped"
  tmux kill-session -t ryu 2>/dev/null && say "Ryu stopped"
  rm -f "$STATE/healing"
}

teardown() {   # back to FirmAE's own wiring: tapN_0.<vid> with 192.168.0.2
  local vid; vid=$(cat "$STATE/vlan" 2>/dev/null || echo 1)
  for n in atk cli; do ip netns delete "$n" 2>/dev/null; ip link delete "v-$n" 2>/dev/null; done
  ovs-vsctl --if-exists del-br "$BR"
  if ip link show "$TAP" >/dev/null 2>&1 && [ "$vid" != 0 ] && ! ip link show "$TAP.$vid" >/dev/null 2>&1; then
    ip link add link "$TAP" name "$TAP.$vid" type vlan id "$vid"; ip link set "$TAP.$vid" up
    ip addr add "$HOST_IP/24" dev "$TAP.$vid"
  fi
  say "bridge removed; twin back on $TAP.$vid"
}

case "${1:-status}" in
  setup) setup ;; attach) attach ;; start|heal) heal ;; status) shift; status "$@" ;;
  watchdog) shift; exec python3 "$HERE/watchdog.py" "$@" ;;
  console) exec tmux attach -t "${2:-twin}" ;; teardown) teardown ;; up) up ;; down) down ;;
  clean) clean_taps; clean_loops; say "cleaned stale taps and loop mounts" ;;
  *) sed -n 2,15p "$0"; exit 1 ;;
esac
