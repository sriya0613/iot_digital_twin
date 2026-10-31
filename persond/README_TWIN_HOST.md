# Person D on the twin host — how to run it

For Sriya (Person A). Everything in `persond/` was built and tested on a laptop with recordings,
`tests/fake_restore.py` and a fake Ryu (`persond/fake_ryu.py`). **None of it has run on the twin yet.**
This page is the checklist for the first run there.

## 1. Copy and install (once)

Copy **only the `persond/` folder** into the detector's folder on the twin host, next to `contracts/`,
`tools/`, `tests/` and `samples/`. Do not copy the zip's other folders over yours: your copies of
`contracts/`, `tools/`, `tests/` and `run_live.sh` may be newer than the ones in the zip.

```
~/firmae/FirmAE/person3/persond/
```

```
cd ~/firmae/FirmAE/person3
pip3 install -r persond/requirements.txt     # jsonschema + streamlit (Python 3.10 is fine)
python3 persond/run_all_tests.py          # must end with ALL PERSON D TESTS PASSED
```

## 2. Check containment by hand first (twin running, nothing else)

```
bash network/twin_net.sh status --json             # note the switch datapath id (dpid)
python3 persond/containment.py --mode ryu --dpid <dpid> isolate 192.168.0.1
python3 persond/containment.py --mode ryu --dpid <dpid> show
ping -c 3 192.168.0.1                               # from the host: should STILL answer (allow rule for 192.168.0.2)
sudo ip netns exec atk ping -c 3 192.168.0.1        # from the attacker: should FAIL (dropped)
python3 persond/containment.py --mode ryu --dpid <dpid> release 192.168.0.1
sudo ip netns exec atk ping -c 3 192.168.0.1        # should answer again
python3 persond/containment.py --mode ryu --dpid <dpid> rate_limit 192.168.0.1   # ok=False = no meter support
python3 persond/containment.py --mode ryu --dpid <dpid> unlimit 192.168.0.1
```

What the rules are (compare with `network/containment_test.sh`):
- isolate: drop `eth_src` / `eth_dst` = `00:de:fa:1a:01:00` at priority 200; allow IPv4 between
  192.168.0.1 and 192.168.0.2 and all ARP at priority 300, so `twin_net.sh heal` can still check the device
- rate-limit: OpenFlow meter 7, 1000 kbit/s, priority 150
- all our rules carry cookies `0xD0000001` / `0xD0000002`; release only deletes those

If a field name is wrong for Ryu 4.34, or the twin's MAC changed, fix `DEVICE_MACS` / the match in
`persond/containment.py` and re-run the checks.

## 3. Full live run (4 terminals)

The detector must run in **alerts-only** mode, so that Person D's engine owns the response
(otherwise the detector heals by itself and our engine only watches).

```
# terminal 1 - twin, bridge, Ryu, watchdog
sudo bash network/twin_net.sh up && bash network/twin_net.sh status

# terminal 2 - detector, alerts only (writes logs/alerts.jsonl)
BRIDGED=1 MODEL_DIR=models_v2 ./run_live.sh --alerts-only

# terminal 3 - Person D: policy + containment + self-healing
python3 persond/run_pipeline.py --follow logs/alerts.jsonl \
    --restore-cmd "sudo -n bash network/twin_net.sh heal" \
    --containment ryu --dpid <dpid>

# terminal 4 - dashboard, open http://localhost:8501
streamlit run persond/dashboard.py
```

Then attack and watch: `sudo ip netns exec atk nmap -T4 -p 1-1000 192.168.0.1`

Expected: risk ~99 -> quarantine -> isolate (verified) -> heal (~70 s) -> release -> 3 low windows ->
heal **verified** on the dashboard. Three attacks within 10 minutes -> device **held**; clear it on the
dashboard (or `python3 persond/healing_engine.py --clear 192.168.0.1`).

`sudo -n` fails instead of asking for a password. Either run terminal 3 in a shell where `sudo` was used a
moment ago, or allow `network/twin_net.sh` in sudoers without a password.

## 4. After the run

```
python3 persond/evaluate.py --out reports/person_d_eval.md
```
Gives heal times, verify results, escalations, containment time and processing delay from `threat.db`.

## Things to check / not known yet

- `BRIDGED=1` together with `--alerts-only` has not been run. If `run_live.sh` does not accept both, the
  detector's own heal must be switched off some other way, or our engine and the detector both heal.
- **The watchdog also heals** the twin when it looks dead. `twin_net.sh heal` lets only one heal run at a time,
  but our engine does not yet know about watchdog heals. Its `health` records are stored raw in threat.db
  (table `health`); send one example line so they can be used for the grace period and the dashboard.
- Containment rules match the MAC, so they survive `twin_net.sh heal` recreating the tap.
- The allow rule for ARP is for all ARP on the bridge, not only the twin's.
