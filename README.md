# Person 3 — threat detection, explanation and auto-heal trigger

Closes the loop of the IoT firmware-twin project:
Person 2's fingerprint windows → **detector** → on attack, run Person 1's `restore.sh`.

## Architecture

```
Module 4 — detection
  Fingerprint vector ─┬─> XGBoost ───────────┐
                      └─> Incremental model ─┴─> Probability fusion ─┬─> Threat probability
                                                                     └─> Threshold logic ─> Threat label

Module 5 — explanation
  Fingerprint + XGBoost model ─> SHAP explainer ─> Feature impact ─> Final risk score
```

| Block | Implementation |
|---|---|
| XGBoost | `XGBClassifier`, 150 trees, depth 2, each tree sees 30% of the features |
| Scan augmentation | Training adds volume-scaled copies of the real scan windows, so the models learn the scan signature and not its size |
| Incremental model | Logistic regression trained by SGD (`SGDClassifier.partial_fit`), can keep learning window by window |
| Probability fusion | `0.6 × p_xgboost + 0.4 × p_incremental` |
| Threshold logic | `< 0.15` benign · `0.15–0.35` suspicious (logged only) · `≥ 0.35` malicious (triggers heal) |
| SHAP explainer | `shap.TreeExplainer` on the XGBoost model |
| Feature impact | Per window: the features that pushed the XGBoost output up or down, largest first |
| Final risk score | `round(100 × threat probability)`, reported with its feature impacts |

All of these values live in `threat_model.py` (`DEFAULTS`) and are saved to `models/config.json`.

## Three monitors: network + syscall + energy (schema 2.0.0)

The project design has three monitors feeding one contextual fingerprint. The first
dataset had only the network monitor. `stream/` now runs all three and emits 45 features
per 5-second window: the same 28 network features, 11 syscall and 6 energy.

| Monitor | Source on the twin host | Features |
|---|---|---|
| Network | packets sniffed on `tap1_0.1` | the 28 from schema 1.0.0, unchanged |
| Syscall | kernel-hook lines the FirmAE kernel writes to `scratch/1/qemu.final.serial.log` (also reads strace output) | count, rate, distinct calls, rare calls, entropy, share of network/file/process calls, execve count, distinct 3-grams, distinct PIDs |
| Energy | the QEMU process sampled once a second: CPU time, I/O operations, page faults, plus network bytes | mean power, peak power, energy in joules, CPU utilisation, I/O operations, energy per syscall |

Energy is a model, not a measurement: `P = P_idle + a*cpu + b*io + c*net + d*mem`,
`E = sum(P*dt)`, with approximate coefficients for a small router SoC (`stream/collectors.py`).

The network-only model in `models/` and its stream in `stream_v1/` are untouched and still
work. The three-monitor model needs a NEW recording, because the old dataset has no
syscall or energy data. On the twin host:

```bash
./syscall_level.sh                 # what the kernel logs now (FirmAE default: level 1, network calls only)
./syscall_level.sh 23              # optional: also log execve, mount, ioctl, unlink, fork, exit, signals
bash ~/firmae/FirmAE/restore.sh    # reboot the twin so the new level applies

./record.sh                        # terminal 1: record all three monitors (Ctrl-C to stop)
# terminal 2, while it records: label what you do
python3 stream/label_run.py --manifest data/run_manifest.jsonl --label benign --seconds 120
python3 stream/label_run.py --manifest data/run_manifest.jsonl --label malware -- sudo nmap -T4 -p 1-1000 192.168.0.1

# build, train, run
python3 stream/run.py build --raw data/raw/*.jsonl --manifest data/run_manifest.jsonl \
        --out data/dataset_v2.jsonl --scaler data/scaler_v2.json
python3 train_detector.py --dataset data/dataset_v2.jsonl --model-dir models_v2 --report-dir reports_v2
MODEL_DIR=models_v2 ./run_live.sh --dry-run
MODEL_DIR=models_v2 ./run_live.sh
```

`sudo bash tests/test_three_monitors.sh` runs this whole chain in about 3 minutes against a
stand-in device (`tests/sim_twin.py`), with no twin needed.

Things to know:

* **A port scan barely touches syscalls or energy.** Closed ports are answered by the
  kernel without any process running. Expect training to report a SHAP share close to
  100% network for scan-only data; syscall and energy features earn their place with
  attacks that run code on the device.
* **The syscall monitor sees kernel-hook events, not every system call.** At FirmAE's
  default level only socket, setsockopt, bind and accept are logged.
* **Windows are now emitted on a timer**, so detection no longer waits for the next
  packet and the background ping is not needed.
* **Unlabelled windows count as normal traffic in training**, except those next to an
  attack window. Do not run an attack while recording without wrapping it in `label_run.py`.

## Files

| File | Purpose |
|---|---|
| `threat_model.py` | Modules 4 + 5: both models, fusion, thresholds, SHAP, risk score, online update |
| `train_detector.py` | Load dataset, clean labels, train, evaluate, save models + report |
| `live_detector.py` | Score each live window, explain it, call `restore.sh` on attack (with cool-down) |
| `common.py` | Feature order + record contract check (schema v1.0.0, 28 features) |
| `plots.py` | Report figures |
| `tests/test_loop.py`, `tests/fake_restore.py` | End-to-end loop test without the twin |
| `run_live.sh` | Starts the live loop on Person 1's host: stream -> detector -> restore |
| `stream/` | Three-monitor stream (schema 2.0.0): `run.py` (record / build / stream), `monitors.py`, `collectors.py`, `pipeline.py`, `label_run.py` |
| `stream_v1/` | The original network-only stream, unchanged; used with the model in `models/` |
| `record.sh`, `syscall_level.sh` | Record raw windows on the twin host; show or change the kernel's syscall logging level |
| `data/`, `contracts/` | Person 2's `dataset.jsonl`, `live_fingerprints.jsonl`, `scaler.json`, schema (copied unchanged) |
| `models/` | `xgboost.json`, `incremental.joblib`, `config.json`, `model_card.json` |
| `reports/evaluation.md` (+ PNGs, `window_scores.csv`) | Results write-up for the report/slides |

## Setup (Windows, Linux or macOS for the offline part)

```bash
pip install -r requirements.txt
python3 train_detector.py        # ALWAYS retrain on the machine that will run the detector
python3 tests/test_loop.py       # should print ALL TESTS PASSED
```

On Windows use `python` instead of `python3`. The live commands (2 and 3 below) need
the Linux host where the twin runs.

Retrain locally because the saved incremental model only loads reliably under the same
scikit-learn version that saved it. Training takes a few seconds.

## Run offline (any machine)

```bash
python3 live_detector.py --input data/dataset.jsonl --dry-run
python3 live_detector.py --input data/live_fingerprints.jsonl --dry-run
python3 live_detector.py --input data/dataset.jsonl --restore-cmd "python tests/fake_restore.py"
```

`data/live_fingerprints.jsonl` is Person 2's recording of the real live stream; its
window 7 is a real `nmap -T4 -p 1-1000` scan.

## Run live (only on Person 1's FirmAE/Mininet host)

The live stream (`tap1_0.1`) and `restore.sh` exist only on that machine, so the whole
`person3` folder has to be copied there.

```bash
# one-time setup on that machine
sudo apt-get install -y python3-pip tcpdump
sudo pip3 install scapy jsonschema          # for root: the sniffer runs under sudo
pip3 install -r requirements.txt            # for your user: the detector
python3 train_detector.py                   # retrain there
python3 tests/test_loop.py

# rehearsal: detect and log only, nothing is restored
./run_live.sh --dry-run

# the full loop
./run_live.sh
```

Then, in a second terminal, attack the twin: `sudo nmap -T4 -p 1-1000 192.168.0.1`.

`run_live.sh` starts the stream that matches the model (`stream_v1/` for `models/`, `stream/` for `models_v2/`), pipes it into the detector, calls
`/home/vboxuser/firmae/FirmAE/restore.sh` on a malicious window, and restarts the stream
if the restore takes the interface down. Change paths with `IFACE=... RESTORE=... ./run_live.sh`.

The equivalent by hand:

```bash
cd stream_v1
sudo python3 run.py stream --iface tap1_0.1 --window 5 --scaler scaler.json --out - \
  | (cd .. && python3 live_detector.py --restore-cmd "bash /home/vboxuser/firmae/FirmAE/restore.sh" --grace 30)
```

A malicious window prints like this:

```
win 7  17:04:42  p=0.995 (xgb 0.99, inc 1.00)  risk 100  MALICIOUS  <- pkt_count +1.31, pkts_per_sec +1.30, frac_tcp +0.71
>> ATTACK DETECTED - running: bash /home/vboxuser/firmae/FirmAE/restore.sh
<< DEVICE HEALED in 84.0 s (exit 0); attack window end -> healed: 96.2 s
```

Every window is appended to `logs/events.jsonl` with both model probabilities, the fused
threat probability, threat label, risk score, SHAP feature impacts and the action taken.

Options: `--confirm N` (consecutive malicious windows before healing, default 1),
`--grace S` (extra seconds ignored after a restore), `--max-heals N` (safety cap,
default 10), `--online-update`, `--save-incremental PATH`.

### Known behaviour to expect in the live run

* **Detection can lag on a quiet network.** Person 2's stream only emits a window when
  a packet from a later window arrives. In the live sample the scan window was followed
  by four silent windows, so it would have been emitted about 20 s late. Keeping a
  `ping 192.168.0.1` running in another terminal during the demo keeps windows flowing.
  Check in `--dry-run` that the ping windows stay benign.
* **The stream may stop during a restore** (QEMU is killed and rebooted). `run_live.sh`
  restarts it; window ids start again from 0, which is fine.
* **Boot traffic is new to the models.** If the first windows after a restore are
  flagged, raise the grace period: `GRACE=60 ./run_live.sh`.
* **Stopping the detector after a heal also stops the twin.** `restore.sh` boots the
  emulator in the background of the same terminal, so Ctrl-C reaches it too (seen in the
  live run: `Network is down` right after Ctrl-C). The emulator also switches the
  terminal to raw mode; the detector puts it back once the restore returns. To keep the
  twin alive after Ctrl-C, Person 1 can change one line in `restore.sh`:
  `sudo setsid ./run.sh -r "$BRAND" "$FIRMWARE" > /tmp/firmae_restore.log 2>&1 < /dev/null &`
  (untested). Otherwise restart the twin after stopping.
* **restore.sh takes 1.5 to 4 minutes** (60 s settle + up to 3 min of polling). The
  detector waits up to 7 minutes before calling it failed.

## Incremental learning (`--online-update`, off by default)

With this flag the incremental model keeps learning during the run: a window whose fused
probability is ≤ 0.05 is learned as normal, ≥ 0.95 as attack, anything in between is
skipped. It is off by default because the model is then learning from its own
predictions with no human label, which has not been tested on live traffic: a mistake it
is confident about gets reinforced. Turn it on for the demo if you want to show the
block working, and use `--save-incremental` only if you want to keep the result.

## Still to confirm on Person 1's machine

1. `restore.sh` is at `/home/vboxuser/firmae/FirmAE/restore.sh` and `save_baseline.sh`
   has been run once (restore.sh exits 1 without a baseline).
2. The stream uses the same `scaler.json` that built the dataset (the copy in `stream/`
   is identical to `data/scaler.json`).
3. `sudo` works without hanging: `run_live.sh` asks for the password once at the start.

## Note on the `personB_to_personC/` subfolder in the handoff zip

That folder holds a different, earlier design (syscall + energy + network features,
20 synthetic records labelled benign/mirai, different schema). It does not match the
28-feature network records the project context describes, so this work uses the
top-level `dataset.jsonl` / `scaler.json` / schema. Check with Person B that this is
the intended dataset.
