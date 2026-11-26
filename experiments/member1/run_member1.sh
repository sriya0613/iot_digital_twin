#!/bin/bash
# experiments/member1/run_member1.sh — Member 1 (Person A) experiments on the twin VM.
#
#   sudo bash experiments/member1/run_member1.sh e13    # spoofing / bypass attempts while quarantined   (~6 min)
#   sudo bash experiments/member1/run_member1.sh e11    # Ryu controller failure during quarantine        (~12 min)
#   sudo bash experiments/member1/run_member1.sh e3     # capture fidelity: mirror port vs ground truth  (~8 min)
#   sudo bash experiments/member1/run_member1.sh all    # all three, in that order                        (~26 min)
#
# Needs: twin, bridge and Ryu up (sudo bash network/twin_net.sh up -> status ALL OK), hping3, tcpdump.
# Every attack is sent from the atk namespace to the twin only. On exit (also Ctrl-C) the script
# releases containment, restores the atk interface and makes sure Ryu is running again.
# Output: reports/member1/<EXP>_<time>.log (raw) and <EXP>_<time>.csv (one row per trial), and a
# RESULT block at the end of the log: paste that back.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
BR=br-twin; TAP=${TAP:-tap1_0}; DEV_IP=192.168.0.1; HOST_IP=192.168.0.2
ATK_IP=192.168.0.10; ATK_MAC=02:00:00:00:00:10; ATK_IF=e-atk
DEV_MAC=$(python3 -c "import sys; sys.path.insert(0,'persond'); from containment import DEVICE_MACS; print(DEVICE_MACS['$DEV_IP'])")
HOST_MAC=$(cat /sys/class/net/twin-host/address)
OUT="$ROOT/reports/member1"; mkdir -p "$OUT"; TS=$(date +%Y%m%dT%H%M%S)
PY="python3 persond/containment.py --mode ryu"
SIZE=1111                                   # ICMP payload size that marks OUR probe packets (ip len 1139)
PROBE_FILTER="(icmp and ip[2:2]=1139) or (vlan and icmp and ip[2:2]=1139)"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }
ryu_up() { [ "$(ovs-vsctl get controller $BR is_connected 2>/dev/null)" = true ]; }
start_ryu() { ryu_up || bash network/twin_net.sh up >>"$LOG" 2>&1; for _ in $(seq 1 30); do ryu_up && return 0; sleep 1; done; return 1; }
kill_ryu() { tmux kill-session -t ryu 2>/dev/null; pkill -f ryu-manager 2>/dev/null; sleep 1; }
our_flows() { ovs-ofctl -O OpenFlow13 dump-flows $BR 2>/dev/null | grep -c 'cookie=0xd000000[12]'; }
failopen_flows() { ovs-appctl bridge/dump-flows $BR 2>/dev/null | grep -c 'priority=15790320'; }   # OVS hidden fail-open flow
ping_ok() { ip netns exec "$1" ping -c 1 -W 1 "$DEV_IP" >/dev/null 2>&1 && echo 1 || echo 0; }
host_ping_ok() { ping -c 1 -W 1 "$DEV_IP" >/dev/null 2>&1 && echo 1 || echo 0; }
port_ctr() { ovs-ofctl -O OpenFlow13 dump-ports $BR "$1" 2>/dev/null | grep -o "$2 pkts=[0-9]*" | cut -d= -f2; }

restore_atk() {
  ip -n atk link set $ATK_IF down 2>/dev/null
  ip -n atk link set $ATK_IF address $ATK_MAC 2>/dev/null
  ip -n atk link set $ATK_IF up 2>/dev/null
  ip -n atk addr del $HOST_IP/32 dev $ATK_IF 2>/dev/null
  ip -n atk addr del $DEV_IP/32 dev $ATK_IF 2>/dev/null
  ip -n atk neigh flush dev $ATK_IF 2>/dev/null
}
cleanup() {
  [ -n "${LOG:-}" ] || return
  log "cleanup: restoring atk interface, starting Ryu if down, releasing containment"
  pkill -f "hping3" 2>/dev/null; pkill -f "tcpdump -i (twin-mon|$TAP|twin-host)" 2>/dev/null
  restore_atk; start_ryu || log "WARNING: Ryu did not come back - run: sudo bash network/twin_net.sh up"
  $PY release $DEV_IP >>"$LOG" 2>&1; $PY unlimit $DEV_IP >>"$LOG" 2>&1
  log "our rules left on switch: $(our_flows) (expect 0)"
}
trap cleanup EXIT

preflight() {
  command -v hping3 >/dev/null || die "hping3 missing: sudo apt install hping3"
  command -v tcpdump >/dev/null || die "tcpdump missing: sudo apt install tcpdump"
  ryu_up || die "Ryu not connected - run: sudo bash network/twin_net.sh up"
  [ "$(host_ping_ok)" = 1 ] || die "host cannot ping the twin - run: sudo bash network/twin_net.sh status"
  [ "$(ping_ok atk)" = 1 ] || die "atk cannot reach the twin before the test (no quarantine should be active)"
  [ "$(our_flows)" = 0 ] || die "containment rules already active - run: $PY release $DEV_IP"
  log "preflight OK  host_mac=$HOST_MAC dev_mac=$DEV_MAC tap=$TAP git=$(git rev-parse --short HEAD)"
}

# count our marked probe packets seen on an interface while running a command
count_on() {   # count_on <iface> <filter> <cmd...>
  local ifc=$1 flt=$2; shift 2; local f; f=$(mktemp)
  tcpdump -i "$ifc" -nn -l "$flt" >"$f" 2>/dev/null & local p=$!; sleep 1
  "$@" >/dev/null 2>&1; sleep 1; kill $p 2>/dev/null; wait $p 2>/dev/null
  wc -l <"$f"; rm -f "$f"
}

# ======================================================================================== E13
e13() {
  local exp=E13; LOG="$OUT/${exp}_$TS.log"; CSV="$OUT/${exp}_$TS.csv"; : >"$LOG"
  echo "case,trial,quarantined,sent,delivered" >"$CSV"
  log "E13 spoofing/bypass: 5 trials x 5 probes per case; delivered = marked probes seen on the target's port"
  preflight
  local probes=5 trials=5
  probe() { ip netns exec atk ping -c $probes -i 0.3 -W 1 -s $SIZE "$@"; }
  record() { echo "$1,$2,$3,$probes,$4" >>"$CSV"; log "  $1 trial $2: delivered $4/$probes"; }

  # C0 control: no quarantine, attacker's own identity -> must be delivered (proves the counting works)
  for t in $(seq 1 $trials); do record C0_control_no_quarantine $t 0 "$(count_on $TAP "$PROBE_FILTER" probe $DEV_IP)"; done
  # C5a control ARP: no quarantine, attacker ARPs for the twin
  for t in $(seq 1 $trials); do ip -n atk neigh flush dev $ATK_IF
    record C5a_control_arp_no_quarantine $t 0 "$(count_on $TAP "(arp and ether src $ATK_MAC) or (vlan and arp and ether src $ATK_MAC)" ip netns exec atk ping -c 1 -W 1 $DEV_IP)"; done

  $PY isolate $DEV_IP >>"$LOG" 2>&1 || die "isolate failed"
  grep -q "verified=True" "$LOG" || die "isolate not verified"
  log "quarantine active ($(our_flows) rules); host ping: $(host_ping_ok)"

  for t in $(seq 1 $trials); do      # C1 own identity
    record C1_own_identity $t 1 "$(count_on $TAP "$PROBE_FILTER" probe $DEV_IP)"; done
  for t in $(seq 1 $trials); do      # C2 spoofed host IP, own MAC
    ip -n atk addr add $HOST_IP/32 dev $ATK_IF 2>/dev/null
    ip -n atk neigh replace $DEV_IP lladdr $DEV_MAC dev $ATK_IF nud permanent
    record C2_spoof_host_ip $t 1 "$(count_on $TAP "$PROBE_FILTER" probe -I $HOST_IP $DEV_IP)"; restore_atk; done
  for t in $(seq 1 $trials); do      # C3 spoofed host MAC + host IP
    ip -n atk link set $ATK_IF down; ip -n atk link set $ATK_IF address $HOST_MAC; ip -n atk link set $ATK_IF up
    ip -n atk addr add $HOST_IP/32 dev $ATK_IF 2>/dev/null
    ip -n atk neigh replace $DEV_IP lladdr $DEV_MAC dev $ATK_IF nud permanent
    record C3_spoof_host_mac_ip $t 1 "$(count_on $TAP "$PROBE_FILTER" probe -I $HOST_IP $DEV_IP)"; restore_atk; done
  for t in $(seq 1 $trials); do      # C4 spoofed device MAC + IP, sending to the host
    ip -n atk link set $ATK_IF down; ip -n atk link set $ATK_IF address $DEV_MAC; ip -n atk link set $ATK_IF up
    ip -n atk addr add $DEV_IP/32 dev $ATK_IF 2>/dev/null
    ip -n atk neigh replace $HOST_IP lladdr $HOST_MAC dev $ATK_IF nud permanent
    record C4_spoof_device_to_host $t 1 "$(count_on twin-host "icmp and ip[2:2]=1139 and ether src $DEV_MAC" \
      ip netns exec atk ping -c $probes -i 0.3 -W 1 -s $SIZE -I $DEV_IP $HOST_IP)"; restore_atk; done
  for t in $(seq 1 $trials); do      # C5 attacker ARP for the twin while quarantined
    ip -n atk neigh flush dev $ATK_IF
    record C5_arp_for_twin $t 1 "$(count_on $TAP "(arp and ether src $ATK_MAC) or (vlan and arp and ether src $ATK_MAC)" ip netns exec atk ping -c 1 -W 1 $DEV_IP)"; done
  for t in $(seq 1 $trials); do      # C6 attacker reaches Ryu REST / dashboard (control plane)
    local r d
    r=$(ip netns exec atk curl -s -m 3 -o /dev/null -w "%{http_code}" http://$HOST_IP:8080/stats/switches); r=${r:-000}
    d=$(ip netns exec atk curl -s -m 3 -o /dev/null -w "%{http_code}" http://$HOST_IP:8501); d=${d:-000}
    echo "C6_control_plane,$t,1,2,$( [ "$r" = 000 ] && [ "$d" = 000 ] && echo 0 || echo 1 )" >>"$CSV"
    log "  C6_control_plane trial $t: ryu=$r dashboard=$d (000 = refused)"; done
  log "host ping during quarantine after all cases: $(host_ping_ok) (expect 1)"
  $PY release $DEV_IP >>"$LOG" 2>&1

  { echo; echo "===== RESULT E13 ($TS, git $(git rev-parse --short HEAD)) ====="
    echo "case                          delivered/sent  (quarantined cases: expect 0; controls: expect >0)"
    awk -F, 'NR>1{s[$1]+=$4; d[$1]+=$5} END{for(k in s) printf "%-30s %d/%d\n", k, d[k], s[k]}' "$CSV" | sort
  } | tee -a "$LOG"
}

# ======================================================================================== E11
e11() {
  local exp=E11; LOG="$OUT/${exp}_$TS.log"; CSV="$OUT/${exp}_$TS.csv"; : >"$LOG"
  echo "case,trial,t_s,ryu_up,our_rules,failopen_rules,atk_reaches,host_reaches" >"$CSV"
  log "E11 controller failure. A: Ryu killed during quarantine, watched 60 s, restarted. B: isolate while Ryu is down."
  preflight
  for t in 1 2 3 4 5; do
    log "A trial $t: isolate"
    $PY isolate $DEV_IP >>"$LOG" 2>&1
    log "  before kill: rules=$(our_flows) atk=$(ping_ok atk) host=$(host_ping_ok)"
    kill_ryu; local t0; t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt 60 ]; do
      local el=$(( $(date +%s) - t0 ))
      echo "A,$t,$el,0,$(our_flows),$(failopen_flows),$(ping_ok atk),$(host_ping_ok)" >>"$CSV"
    done
    local leak; leak=$(awk -F, -v t=$t '$1=="A"&&$2==t&&$7==1{print $3; exit}' "$CSV")
    log "  Ryu down 60 s: first attacker packet through at t=${leak:-never} s; rules at end=$(our_flows); fail-open rules=$(failopen_flows)"
    start_ryu || die "Ryu did not restart"
    sleep 3
    echo "A,$t,after_restart,1,$(our_flows),$(failopen_flows),$(ping_ok atk),$(host_ping_ok)" >>"$CSV"
    log "  after Ryu restart: rules=$(our_flows) fail-open=$(failopen_flows) atk=$(ping_ok atk) host=$(host_ping_ok)"
    $PY release $DEV_IP >>"$LOG" 2>&1; sleep 10
  done
  for t in 1 2 3 4 5; do
    kill_ryu
    local res; res=$($PY isolate $DEV_IP 2>&1 | tail -1); echo "$res" >>"$LOG"
    echo "B,$t,0,0,$(our_flows),$(failopen_flows),$(ping_ok atk),$(host_ping_ok)" >>"$CSV"
    log "B trial $t: isolate with Ryu down -> $(echo "$res" | grep -o "'ok': [A-Za-z]*") rules=$(our_flows) atk=$(ping_ok atk)"
    start_ryu || die "Ryu did not restart"; $PY release $DEV_IP >>"$LOG" 2>&1; sleep 5
  done
  { echo; echo "===== RESULT E11 ($TS, git $(git rev-parse --short HEAD)) ====="
    awk -F, '$1=="A"&&$3!="after_restart"{n[$2]++; a[$2]+=$7; if($7==1&&!($2 in f)) f[$2]=$3; r[$2]=$5; o[$2]=$6}
             $1=="A"&&$3=="after_restart"{ar[$2]=$5" rules, atk="$7}
             END{for(t=1;t<=5;t++) printf "A trial %d: attacker reached twin in %d/%d one-second probes while Ryu down; first leak t=%s s; rules at 60 s=%s; fail-open rules=%s; after restart: %s\n", t, a[t], n[t], (t in f)?f[t]:"never", r[t], o[t], ar[t]}' "$CSV"
    awk -F, '$1=="B"{printf "B trial %d: isolate with Ryu down -> rules installed=%s, attacker reaches twin=%s\n", $2, $5, $7}' "$CSV"
  } | tee -a "$LOG"
}

# ======================================================================================== E3
e3() {
  local exp=E3; LOG="$OUT/${exp}_$TS.log"; CSV="$OUT/${exp}_$TS.csv"; : >"$LOG"
  echo "rate,trial,atk_port_rx,tap_tx,mirror_seen,mirror_kernel_drops" >"$CSV"
  log "E3 capture fidelity: 10 s SYN stream at 3 rates x 3 trials; atk port rx (sent) vs tap tx (delivered) vs mirror capture"
  preflight
  local SYN="(tcp[13]&2!=0 and src host $ATK_IP and dst host $DEV_IP) or (vlan and tcp[13]&2!=0 and src host $ATK_IP and dst host $DEV_IP)"
  for rate in 1000 10000 flood; do
    local opt; case $rate in 1000) opt="-i u1000";; 10000) opt="-i u100";; flood) opt="--flood";; esac
    for t in 1 2 3; do
      local pc err; pc=$(mktemp); err=$(mktemp)
      tcpdump -i twin-mon -nn -B 65536 -s 96 -w "$pc" 2>"$err" & local tp=$!; sleep 2
      local a1 b1; a1=$(port_ctr v-atk rx); b1=$(port_ctr $TAP tx)
      ip netns exec atk timeout 10 hping3 -S $opt -p 80 $DEV_IP >/dev/null 2>&1
      sleep 1; local a2 b2; a2=$(port_ctr v-atk rx); b2=$(port_ctr $TAP tx)
      kill -INT $tp 2>/dev/null; wait $tp 2>/dev/null
      local seen drops; seen=$(tcpdump -r "$pc" -nn "$SYN" 2>/dev/null | wc -l)
      drops=$(grep -o '[0-9]* packets dropped by kernel' "$err" | cut -d' ' -f1); drops=${drops:-0}
      echo "$rate,$t,$((a2-a1)),$((b2-b1)),$seen,$drops" >>"$CSV"
      log "  rate=$rate trial $t: sent(atk rx)=$((a2-a1)) delivered(tap tx)=$((b2-b1)) mirror_seen=$seen kernel_drops=$drops"
      rm -f "$pc" "$err"
      for _ in $(seq 1 30); do [ "$(host_ping_ok)" = 1 ] && break; sleep 1; done; sleep 15   # let the twin recover
    done
  done
  { echo; echo "===== RESULT E3 ($TS, git $(git rev-parse --short HEAD)) ====="
    echo "rate      sent      delivered  mirror_seen  mirror/delivered  kernel_drops   (means of 3 trials)"
    awk -F, 'NR>1{n[$1]++; s[$1]+=$3; d[$1]+=$4; m[$1]+=$5; k[$1]+=$6}
             END{split("1000 10000 flood",o," "); for(i=1;i<=3;i++){r=o[i]; if(!(r in n)) continue;
                 printf "%-8s %9.0f %10.0f %12.0f %16.3f %13.0f\n", r, s[r]/n[r], d[r]/n[r], m[r]/n[r], (d[r]>0?m[r]/d[r]:0), k[r]/n[r]}}' "$CSV"
  } | tee -a "$LOG"
}

case "${1:-}" in
  e13) e13 ;; e11) e11 ;; e3) e3 ;;
  all) e13; TS=$(date +%Y%m%dT%H%M%S); e11; TS=$(date +%Y%m%dT%H%M%S); e3 ;;
  *) sed -n 2,14p "$0"; exit 1 ;;
esac
