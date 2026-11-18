# Data Collection Protocol (Phase 4)

Goal: independent sessions so the final test set has **≥ 3 independent attack episodes per class from sessions never used in training**.

## Environment (must match the existing data)

| Item | Value |
|---|---|
| Host | Ubuntu VM (VirtualBox), FirmAE at `$FIRMAE_DIR` (default `/home/vboxuser/firmae/FirmAE`) |
| Firmware | D-Link DIR-868L `DIR-868L_revB_2-05b02`, IID 1 |
| Twin IP / host IP | 192.168.0.1 / 192.168.0.2 |
| Bridge | OVS `br-twin`, mirror port `twin-mon`; recorder on `tap1_0.1` |
| Namespaces | `atk` 192.168.0.10 (attacks), `cli` 192.168.0.20 (benign) |
| Controller | Ryu, OpenFlow 1.3, REST :8080 |
| Packages | `python3 -m pip install -r requirements.txt`; apt: `nmap hping3 curl tshark openvswitch-switch` |
| Window | 5 s, schema 2.0.0 (28 network + 11 syscall + 6 energy) |

## Safety

- All attacks are **simulated** traffic generators (nmap, hping3, curl loops). No malware binaries.
- `atk` must have **no default route**; `collect_session.sh` refuses to run otherwise.
- Everything stays on `br-twin`; nothing is sent outside the VM.
- Run inside a VM snapshot; revert the snapshot if the twin misbehaves.

## One session (≈ 25 min)

```bash
./twin.sh restart                 # clean baseline; wait until ./twin.sh status says ping answers
./record.sh                       # terminal 1 - leave running
SESSION_TAG="S07 operator=<name>" ./scripts/run_protocol.sh   # terminal 2
# Ctrl-C record.sh when run_protocol.sh says complete
```

`run_protocol.sh` runs: benign-http, benign-ping, then scan, scan-slow, bruteforce, dos, beacon in a per-session shuffled order with benign traffic after each attack, then a labelled heal.

Single episodes: `./scripts/collect_session.sh <benign-http|benign-ping|scan|scan-slow|bruteforce|dos|beacon|heal>`.

## Independence rules

1. Each session starts from `./twin.sh restart` and a new `record.sh` file.
2. At most 2 sessions per day; vary the operator where possible.
3. Never run two scenarios at once; `collect_session.sh` leaves a 15 s idle gap before each attack.
4. Assign sessions to train / val / test **by session before looking at any results**, e.g. sessions 1–9 train, 10–12 val, 13–15+ test. Write the assignment into `data/session_split.json` and commit it before training.

## Build and validate

```bash
./scripts/build_dataset.sh data/dataset_v4.jsonl        # all raw sessions in one pass
python3 -I scripts/validate_session.py data/dataset_v4.jsonl --min-episodes 3
```

Expected outputs: `data/raw/session_<UTC time>.jsonl` per recorder run, new lines in `data/run_manifest.jsonl`, and `data/dataset_v4.jsonl` + `data/dataset_v4.jsonl.scaler.json`.

The validator FAILS on missing features, dead syscall/energy monitors, or malware windows without `attack_class`. It WARNS on < 3 episodes per class, very short attacks, gaps > 30 s, and duplicate windows.

## Known limitation

`stream/run.py build` refits the min-max scaler on all raw files given, so scaling bounds include test sessions. This is stated in threats to validity.
