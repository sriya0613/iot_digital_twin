# EXP-6b: Why the detector false-alarms on Oct 3 benign traffic

**Status**: diagnostic. Model = paper detector trained on all Oct 16 + Oct 19 supervised windows.

Oct 3 benign windows flagged: **25 of 37**.

## Features that differ most (benign v3 vs benign Oct 3)

| Feature | Monitor | KS | mean v3 benign | mean Oct 3 benign | Oct 3 above v3 max |
|---|---|---|---|---|---|
| `energy_cpu_util` | energy | 0.96 | 0.0669 | 0.2441 | 46% |
| `mean_ttl` | network | 0.70 | 0.2240 | 0.1768 | 70% |
| `frac_icmp` | network | 0.68 | 0.2857 | 0.0105 | 0% |
| `n_unique_src_ports` | network | 0.62 | 0.0001 | 0.0003 | 62% |
| `frac_ack` | network | 0.62 | 0.5141 | 0.6642 | 0% |
| `n_unique_dst_ports` | network | 0.60 | 0.0008 | 0.0021 | 59% |
| `distinct_l4_services` | network | 0.60 | 0.0008 | 0.0021 | 59% |
| `energy_per_syscall` | energy | 0.60 | 0.0138 | 0.0188 | 0% |
| `energy_mean_power` | energy | 0.59 | 0.0458 | 0.0629 | 32% |
| `frac_syn` | network | 0.58 | 0.0860 | 0.0065 | 0% |
| `energy_j` | energy | 0.57 | 0.0440 | 0.0598 | 14% |
| `std_iat` | network | 0.52 | 0.1725 | 0.0630 | 0% |

## Features SHAP blames for the false alarms (count of flagged windows where the feature is a top-3 risk-raising contributor)

- `energy_cpu_util` (energy): 25
- `energy_mean_power` (energy): 11
- `pkt_count` (network): 10
- `frac_tcp` (network): 2
- `frac_udp` (network): 1
- `pkts_per_sec` (network): 1

## Same model without the energy monitor

| Feature set | Oct 3 benign FPR | Oct 3 scan recall |
|---|---|---|
| network (28) | 0.541 | 1.000 |
| network+syscall (39) | 0.405 | 1.000 |
| all 3 monitors (45) | 0.676 | 1.000 |

## Interpretation

1. **Energy features are host-dependent.** `energy_cpu_util` and the power features measure the QEMU process on the host, so they move with host load and twin uptime, not only with what the device does. They separate the sessions almost perfectly (KS near 1) while carrying the label in training, which is a shortcut a model can learn.
2. **Oct 3 used a different network setup.** Its manifest shows attacks run as `sudo nmap ...` from the host; Oct 16 ran them from the `atk` namespace. TTL, port-count and ICMP features shift accordingly, so Oct 3 differs in environment as well as session.
3. Consequence for the paper: within-session results (EXP-3/5/6) do not show cross-session generalisation. Phase 4 sessions must keep the topology fixed and record host load, and the energy features need a per-session baseline normalisation (or removal) before they can be claimed as a benefit.

Fixed topology for Phase 4 is enforced by `scripts/collect_session.sh` (all traffic from `atk`/`cli`).
