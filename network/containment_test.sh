#!/bin/bash
# network/containment_test.sh — prove the SDN path works and time it.
# Blocks the attacker namespace (atk) with a drop rule, checks atk is cut off while the
# normal client (cli) still reaches the twin, then removes the rule.
# Uses Ryu's REST API if Ryu is running, otherwise ovs-ofctl directly.
[ "$(id -u)" = 0 ] || exec sudo -E bash "$0" "$@"
BR=${BR:-br-twin}; DEV_IP=${DEV_IP:-192.168.0.1}; MAC=${MAC:-02:00:00:00:00:10}
DPID=$((16#$(ovs-vsctl get bridge "$BR" datapath_id | tr -d '"')))
REST=http://127.0.0.1:8080/stats/flowentry
if curl -s -m 2 "http://127.0.0.1:8080/stats/switches" >/dev/null; then VIA=ryu; else VIA=ovs-ofctl; fi
echo "[containment] using $VIA"
ip netns exec atk ping -c 2 -W 1 "$DEV_IP" >/dev/null && echo "  before: atk reaches twin" || echo "  before: atk CANNOT reach twin (fix this first)"
T0=$(date +%s.%N)
if [ $VIA = ryu ]; then
  curl -s -X POST -d "{\"dpid\": $DPID, \"priority\": 100, \"match\": {\"eth_src\": \"$MAC\"}, \"actions\": []}" $REST/add
else
  ovs-ofctl -O OpenFlow13 add-flow "$BR" "priority=100,dl_src=$MAC,actions=drop"
fi
until ovs-ofctl -O OpenFlow13 dump-flows "$BR" | grep -q "dl_src=$MAC"; do sleep 0.05; done
T1=$(date +%s.%N)
awk -v a="$T0" -v b="$T1" 'BEGIN{printf "  rule active after %.3f s\n", b-a}'
ip netns exec atk ping -c 2 -W 1 "$DEV_IP" >/dev/null && echo "  FAIL: atk still reaches twin" || echo "  OK: atk is cut off"
ip netns exec cli ping -c 2 -W 1 "$DEV_IP" >/dev/null && echo "  OK: cli still reaches twin" || echo "  FAIL: cli also cut off"
if [ $VIA = ryu ]; then
  curl -s -X POST -d "{\"dpid\": $DPID, \"priority\": 100, \"match\": {\"eth_src\": \"$MAC\"}}" $REST/delete_strict
else
  ovs-ofctl -O OpenFlow13 --strict del-flows "$BR" "priority=100,dl_src=$MAC"
fi
ip netns exec atk ping -c 2 -W 1 "$DEV_IP" >/dev/null && echo "  after removal: atk reaches twin again" || echo "  after removal: atk still blocked"
