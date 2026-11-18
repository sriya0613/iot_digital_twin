# Oct 3 Raw Data Reconstruction (v2 — corrected)

**Correction to Phase 1:** the Phase 1 version of this script wrote raw, unscaled values (e.g. `pkt_count` up to 897) while dataset_v3 is min-max scaled to [0,1]. Its claim of "fully compatible" was wrong. Phase 1 also said the Oct 3 sessions had no labels; in fact `data/run_manifest.jsonl` labels them. This version rescales with the frozen `scaler_v3.json` and labels from the manifest using `stream/pipeline.py`.

**Windows**: 261 from 6 raw files

| File | Windows |
|---|---|
| `session_20261003T095216.jsonl` | 123 |
| `session_20261003T102309.jsonl` | 46 |
| `session_20261003T102718.jsonl` | 41 |
| `session_20261003T103100.jsonl` | 49 |
| `session_20261003T103513.jsonl` | 2 |
| `session_20261003T103529.jsonl` | 0 |

## Labels (from manifest)

| label | attack_class | windows |
|---|---|---|
| benign | - | 37 |
| healing | - | 126 |
| malware | scan | 9 |
| unlabeled | - | 89 |

**Labelled runs**: benign/-:37, healing/-:45, healing/-:41, healing/-:40, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1, malware/scan:1

**attack_class provenance**: the Oct 3 manifest has no `attack_class` field. Every Oct 3 malware run's recorded command is `sudo nmap -T4 -p 1-1000 192.168.0.1`, so these windows are marked `scan` with `attack_class_source = inferred_from_manifest_command`.

## Scale check

Raw values outside the v3 scaler's range were clipped to [0,1] (count of windows per feature):

- `frac_ack`: 73
- `std_pkt_size`: 20
- `mean_pkt_size`: 9
- `mean_iat`: 3
- `energy_per_syscall`: 3
- `frac_other`: 3

Features constant across Oct 3 supervised windows (6): `n_dhcp`, `sys_rare_count`, `sys_frac_net`, `sys_frac_file`, `sys_frac_proc`, `sys_n_exec`

## Use

Oct 3 is a separate day, twin boot and recorder run from the Oct 16 training data, so its benign and scan windows serve as a **cross-session test** (Phase 2, EXP-6). It contains one attack class (scan, lower-volume `-p 1-1000` than Oct 16's `-p 1-65535`) and one benign run.
