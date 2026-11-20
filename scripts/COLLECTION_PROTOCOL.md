# Data Collection Protocol (Phase 4) — protocol v2.0

Goal: independent sessions so the final test set has **≥ 3 independent attack episodes per class from sessions never used in training**.

## Environment (must match the existing data)

| Item | Value |
|---|---|
| Host | Ubuntu VM (VirtualBox), FirmAE at `$FIRMAE_DIR` (default `/home/vboxuser/firmae/FirmAE`) |
| Firmware | D-Link DIR-868L `DIR-868L_revB_2-05b02`, IID 1 |
| Twin IP / host IP | 192.168.0.1 / 192.168.0.2 |
| Bridge | OVS `br-twin`, mirror port `twin-mon` |
| **Capture interface** | **`twin-mon`** — run the recorder as `IFACE=twin-mon ./record.sh`. The Oct 16/19 training data were captured on `twin-mon`; `record.sh`'s default `tap1_0.1` is the pre-bridge capture point used on Oct 3 and gives different features. `collect_session.sh` refuses to run if the recorder is on any other interface. |
| Namespaces | `atk` 192.168.0.10 (attacks), `cli` 192.168.0.20 (benign) |
| Controller | Ryu, OpenFlow 1.3, REST :8080 |
| Packages | `python3 -m pip install -r requirements.txt`; apt: `nmap hping3 curl tcpdump sqlite3 openvswitch-switch` |
| Window | 5 s, schema 2.0.0 (28 network + 11 syscall + 6 energy) |

Check the environment first (read-only, changes nothing): `bash scripts/check_env.sh`.

**No self-healing watchdog during collection.** `twin_net.sh up` normally starts `network/watchdog.py`, which
restores the twin when ping/HTTP fail for ~15 s. A DoS or bruteforce episode causes exactly that, so the
watchdog would restore the twin in the middle of attack data (pilot S00). Bring the twin up with
`sudo NOWATCHDOG=1 bash network/twin_net.sh up`; `collect_session.sh` refuses to run while a healing watchdog
is active (a `--no-heal` watchdog is allowed). The watchdog is used again in Phase 3, where healing is tested.

## Safety

- All attacks are **simulated** traffic generators (nmap, hping3, curl loops). No malware binaries.
- `atk` must have **no default route**; `collect_session.sh` refuses to run otherwise.
- Everything stays on `br-twin`; nothing is sent outside the VM.
- Take a VM snapshot before the first session; revert it if the twin misbehaves.

## Sessions

Session IDs are `S01`–`S99`, never reused (`kit.py` refuses to overwrite `data/sessions/<id>.json`).
Pilots use `P01`–`P99` (S00 was the first pilot, before P IDs existed): they check the kit end to end, are
rejected by the split loader, and are **never** used in results.

**Before S01**, write `data/session_split.json` (which session IDs are train / val / test) and commit it. Assignment is decided before any session is collected or looked at.

## One session (≈ 40 min)

```bash
sudo bash network/twin_net.sh down                 # clean baseline, no watchdog
sudo NOWATCHDOG=1 bash network/twin_net.sh up
bash network/twin_net.sh status                    # wait for ALL OK; then ~2 min for the web server
IFACE=twin-mon ./record.sh                         # terminal 1 - leave running
SESSION_ID=S07 SESSION_TAG="operator=<name>" ./scripts/run_protocol.sh   # terminal 2 (asks for sudo once)
# Ctrl-C record.sh when run_protocol.sh says complete
```

Keep the VM and the host awake (no suspend; screen lock is fine). Before every episode the preflight waits up
to 120 s for the twin to answer ping **and** HTTP; any wait is logged to `data/preflight_waits.jsonl`
(after a DoS this is the twin's recovery time). `record.sh` leaves an empty raw file when stopped;
`build_dataset.sh` skips it.

`run_protocol.sh`:
1. writes `data/sessions/S07.json` (start time, host load, QEMU uptime, tool versions, git commit, model hash, episode order);
2. runs benign-idle, benign-http, benign-ping, benign-burst;
3. runs scan, scan-slow, bruteforce, dos, beacon, beacon-long in an order shuffled by the session ID, with benign-http after each attack;
4. runs a labelled heal;
5. records stop time and status (`complete`, or `aborted` if any step failed).

| Scenario | Label | What it does | ≈ time |
|---|---|---|---|
| benign-idle | benign | no traffic from us for 120 s | 2 min |
| benign-http | benign | GET / every 3 s, 40 times | 2 min |
| benign-ping | benign | 60 pings | 1 min |
| benign-burst | benign | browser-like: 10–20 parallel GETs every 15–30 s for 120 s (hard negative for bruteforce) | 2 min |
| scan | scan | `nmap -T4 -p 1-65535` | ~0.5 min |
| scan-slow | scan | `nmap -T2 --top-ports 100` | ~1 min |
| bruteforce | bruteforce | 1500 basic-auth GETs | ~4 min |
| dos | dos | 20 s SYN flood | 0.5 min |
| beacon | beacon | GET / every 5 s for 60 s (Oct 16 variant) | 1 min |
| beacon-long | beacon | GET / every 10, 30 or 60 s (rotates by session: S01→10, S02→30, S03→60, …) ± 20% jitter, 300 s; every request time logged to `data/beacon_requests.jsonl` | 5 min |
| heal | healing | `twin_net.sh heal` + 150 s | 4–6 min |

Single episodes: `SESSION_ID=S07 ./scripts/collect_session.sh <scenario>`.

## Independence rules

1. Each session starts from `./twin.sh restart` and a new `record.sh` run on `twin-mon`.
2. At most 2 sessions per day; vary the operator where possible.
3. Never run two scenarios at once; `collect_session.sh` leaves a 15 s idle gap before each attack.
4. Never change the protocol mid-collection. A change means a new `PROTOCOL_VERSION` in `scripts/kit.py`, recorded in every session file.

## Build and validate

```bash
./scripts/build_dataset.sh data/dataset_v4.jsonl             # all non-empty raw files captured on twin-mon
python3 -I scripts/merge_sessions.py data/dataset_v4.jsonl    # writes data/dataset_v4_sessions.jsonl
python3 -I scripts/validate_session.py data/dataset_v4_sessions.jsonl --min-episodes 3
```

`merge_sessions.py` never modifies its input. Windows earlier than the first session file become legacy sessions (`L20261016`, `L20261019`); windows between sessions get no session; a labelled window outside every session is an error (exit 1).

Expected outputs: `data/raw/session_<UTC time>.jsonl` per recorder run, new lines in `data/run_manifest.jsonl`, `data/sessions/<id>.json` per session, `data/beacon_requests.jsonl`, `data/dataset_v4.jsonl` + `data/dataset_v4.jsonl.scaler.json`, and `data/dataset_v4_sessions.jsonl` (the file used for evaluation, split by `data/session_split.json`).

The validator FAILS on missing features, dead syscall/energy monitors, or malware windows without `attack_class`. It WARNS on < 3 episodes per class, very short attacks, gaps > 30 s, and duplicate windows.

## Known limitation

`stream/run.py build` refits the min-max scaler on all raw files given, so scaling bounds include test sessions. This is stated in threats to validity.
