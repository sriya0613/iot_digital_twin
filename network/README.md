# Person A — digital twin, network and healing infrastructure

Everything here runs on the twin host (`vboxuser@capstone`, folder `~/firmae/FirmAE/person3`).

## Start and stop

```
sudo bash network/twin_net.sh up        # bridge + Ryu + twin + watchdog, all in the background
bash network/twin_net.sh status         # must end with ALL OK
sudo bash network/twin_net.sh down      # stop watchdog, twin and Ryu
```

`up` is safe to run again at any time: it only starts what is not running, and leaves a
healthy twin alone. Use it after every VM restart. (Saving the VirtualBox machine state
keeps everything running; stop the watchdog first and check `status` after resuming.)

Background windows (leave with **Ctrl-b then d**, type nothing else in the twin's window):

```
sudo bash network/twin_net.sh console twin       # the emulator
sudo bash network/twin_net.sh console ryu        # the controller
sudo bash network/twin_net.sh console watchdog   # liveness checks
```
Logs: `network/.state/ryu.log`, `network/.state/watchdog.log`.

## How the twin is wired

```
twin (QEMU, D-Link DIR-868L) --tap1_0--+                     +-- twin-host  192.168.0.2   this host (restore checks, scans, browser)
                                       |    br-twin (OVS)    +-- atk        192.168.0.10  attacker test host (network namespace)
Ryu controller (OpenFlow 1.3) ---------+                     +-- cli        192.168.0.20  normal client test host (network namespace)
                                                             +-- twin-mon   mirror: a copy of every packet, for the monitors
```

- Twin: 192.168.0.1, MAC 00:de:fa:1a:01:00. The firmware tags its LAN frames with VLAN 1, so its
  tap is a VLAN-1 trunk and every other port is an access port on VLAN 1.
- `twin-host` copies the MAC of FirmAE's old `tap1_0.1` interface on every attach: the firmware
  keeps the host's MAC in its ARP cache and never updates it.
- The bridge runs `fail_mode=standalone`: if Ryu stops, traffic keeps flowing as a normal switch
  (fail-open); containment rules need Ryu (or `ovs-ofctl`) to be added.
- Ryu: `ryu-manager ryu.app.ofctl_rest network/ryu_base.py` in `~/ryu-venv` (Ryu 4.34 on Python
  3.10 needs eventlet 0.33.3 and a one-line patch in `ryu/app/wsgi.py`: `ALREADY_HANDLED = []`).
  `ryu_base.py` installs one rule: priority 0, normal switching. REST API on http://127.0.0.1:8080.

## Healing

`twin_net.sh heal` (= `start`): stop the twin, copy the clean baseline disk back (`restore.sh`),
reboot the firmware in the background tmux session `twin`, re-attach it to the bridge, and report
success only when 192.168.0.1 answers through the bridge. Only one heal runs at a time; a second
caller waits for the first and reports its result.

Who calls it:
- the detector on an attack: `BRIDGED=1 MODEL_DIR=models_v2 ./run_live.sh` (via `network/heal_bridged.sh`)
- the watchdog when the twin is dead: 3 failed checks in a row (emulator / ping / web page, every 5 s),
  escalates after 2 heals that do not bring it back (`network/watchdog.py`)
- Person D's self-healing engine

### Re-saving the clean baseline
Only if the firmware or its FirmAE setup changes. With a freshly booted, known-clean twin:
stop it (`sudo bash network/twin_net.sh down`), then run Person A's `save_baseline.sh` in
`~/firmae/FirmAE` (it copies `scratch/1/image.raw` to `scratch/1/image.baseline.raw`), then
`sudo bash network/twin_net.sh up`.

## What the other parts use

| Who | Uses |
|---|---|
| Person B (monitors) | capture interface `twin-mon` (`IFACE=twin-mon ./record.sh ...`); attacks from `sudo ip netns exec atk ...`, normal traffic from `sudo ip netns exec cli ...` |
| Person C (detector) | `BRIDGED=1 ./run_live.sh` captures on `twin-mon` and heals through `heal_bridged.sh` |
| Person D (policy, response, dashboard) | `twin_net.sh heal`; Ryu REST on :8080 (switch `datapath id` from `status`); `bash network/twin_net.sh status --json` and `network/.state/health.json`; `health` records in `logs/alerts.jsonl` |

`containment_test.sh` shows the REST call that adds and removes a drop rule, and times it.

## Measured (14 Oct 2026)

| | |
|---|---|
| containment rule active | 0.104 s |
| heal (detached restore + re-attach) | 68–77 s over 8 runs, 0 failures |
| dead twin noticed | ~18 s (3 checks × 5 s) |
| dead twin back up | ~70 s after it was noticed |
| scan from `atk` detected | first 5-s window, p = 0.99 |

## Files

| file | what |
|---|---|
| `twin_net.sh` | bridge, test hosts, mirror, start/heal/attach, status, up/down |
| `watchdog.py` | liveness checks, dead-node healing, `health.json`, `status --json` |
| `heal_bridged.sh` | the restore command the detector runs |
| `ryu_base.py` | the base Ryu app (normal switching) |
| `containment_test.sh` | proves and times a containment rule through Ryu |
