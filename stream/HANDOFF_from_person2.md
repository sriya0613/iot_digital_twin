# Handoff to Person 3 — Fingerprint Detector Integration

Everything Person 3 needs to build the anomaly detector and close the self-healing loop.

---

## Files in this bundle (8)

### Code — the fingerprinting pipeline (needed together, do not split)
| File | Purpose |
|------|---------|
| `run.py` | CLI: `build` (dataset) and `stream` (live) |
| `pipeline.py` | windowing, labeling, normalization, record assembly |
| `collectors.py` | the three collectors (statistical / protocol / service) |
| `contracts/fingerprint.schema.json` | schema v1.0.0 — validate records against it |

### Data — for training and testing the detector
| File | Purpose |
|------|---------|
| `dataset.jsonl` | labeled training data (benign / malware / unlabeled) |
| `scaler.json` | the fitted min-max normalizer (features already scaled) |
| `live_fingerprints.jsonl` | REAL live-stream sample, including a genuine nmap attack window |

### From Person 1 (the twin host)
| File | Purpose |
|------|---------|
| `restore.sh` | heals the twin to clean baseline (~1 min). The detector calls this on attack. |

---

## The 3 facts Person 3 must know

1. **Live stream command** (runs on Person 1's machine, where the twin is):
   ```
   sudo python3 run.py stream --iface tap1_0.1 --window 5 --scaler scaler.json --out - | python3 person3_detector.py
   ```
   Interface is `tap1_0.1` (NOT mirror-host). Window is 5s. `scaler.json` must be in the folder.

2. **The emulated router runs on Person 1's machine** — Ubuntu FirmAE/Mininet host
   (`vboxuser@capstone`). Device is at `192.168.0.1`, reachable on interface `tap1_0.1`.
   `restore.sh` lives in `~/firmae/FirmAE/` on that machine and heals the twin in ~1 min,
   but it **only runs on that machine** (it controls the local QEMU VM).

3. **The detector must run on Person 1's machine** — that is the only place where BOTH the
   live stream (`tap1_0.1`) and `restore.sh` exist. So either:
   - Person 3 hands `person3_detector.py` to Person 1 to run there, OR
   - Person 3 runs their detector on Person 1's host directly.
   It cannot close the loop from a separate laptop (no live feed, no restore there).

---

## Record format (one JSON object per line)

```
schema_version, window_id, window_start_epoch, window_end_epoch,
device_ip, firmware_id, mirror_if,
label  (benign | malware | healing | unlabeled),
run_id,
features { 28 floats, all min-max normalized to [0,1] },
meta { normalization, n_features }
```

### The 28 features (fixed order)
- **statistical (8):** pkt_count, byte_count, mean_pkt_size, std_pkt_size, mean_iat, std_iat,
  pkts_per_sec, bytes_per_sec
- **protocol (11):** frac_tcp, frac_udp, frac_icmp, frac_arp, frac_other, n_unique_src_ports,
  n_unique_dst_ports, frac_syn, frac_ack, frac_rst, mean_ttl
- **service (9):** n_dns_mdns, n_dhcp, n_arp_req, n_arp_reply, n_http, n_https, n_broadcast,
  n_multicast, distinct_l4_services

---

## How to consume

**Training (offline, from `dataset.jsonl`):**
- read each line, skip `label == "unlabeled"`
- lock feature column order from the first record's `features` keys
- build X from feature values, y from `label`

**Live inference (from the stream):**
- read each JSON line as it arrives
- score the 28-feature vector with your model
- on attack → run Person 1's `restore.sh` to heal the twin

Features arrive already normalized to [0,1] via `scaler.json` — do NOT re-normalize.
Keep window = 5s and schema = 1.0.0 fixed across training and inference.

---

## Verified attack signature (from the live sample)

A port-scan window looks VERY different from idle. In `live_fingerprints.jsonl`, compare the
idle windows to the attack window — during the nmap scan:

| feature | idle | attack |
|---------|------|--------|
| frac_tcp | 0.0 | ~1.0 |
| frac_syn | 0.0 | high (~0.64) |
| frac_rst | 0.0 | ~1.0 |
| n_unique_dst_ports | ~0.001 | ~0.23 |
| pkts_per_sec | ~0.0001 | ~0.018 (≈185× higher) |

The classes separate so cleanly that even a simple threshold rule works, though an ML model
(e.g. IsolationForest trained on benign, or a supervised classifier) is the proper approach.

---

## Setup on Person 1's machine (one-time)

```
sudo apt-get install -y python3 python3-pip tcpdump
sudo pip3 install scapy jsonschema     # install for root — the live stream needs root to sniff
```

## The full self-healing loop (the demo)

1. Twin running on Person 1's host (`ping 192.168.0.1` works).
2. Stream + detector: `sudo python3 run.py stream --iface tap1_0.1 --window 5 --scaler scaler.json --out - | python3 person3_detector.py`
3. Attack: `sudo nmap -T4 -p 1-1000 192.168.0.1`
4. Detector flags the attack window → calls `restore.sh` → twin heals → traffic returns to benign.
