# Member 1 (Person A) — implementation fixes and experiments, 2026-11-26

All runs on the twin VM (FirmAE D-Link DIR-868L 2.05b02, OVS `br-twin`, Ryu 4.34, OpenFlow 1.3),
branch `phase3-prep`. Script: `experiments/member1/run_member1.sh`. Raw logs and per-trial CSVs are
on the VM under `reports/member1/` (E13_20261126T114821, E11_20261126T124719, E3_20261126T131007).

## Fixes (master plan IDs)

| ID | Fix | Commit | Live check |
|---|---|---|---|
| IMP-01 | Allow rules pinned to MAC+IP (+ `twin-host` port); anti-spoof drops; ARP limited | afd6252 | host 3/3, attacker 0/3; E13 below |
| IMP-04 | Read-back compares each rule's priority, match, actions | afd6252 | verified=True with Ryu's OF1.0 field names |
| IMP-02 | Ryu REST bound to 127.0.0.1 (was 0.0.0.0, reachable from attacker) | fa01193 | atk → 8080 refused |
| IMP-03 | Dashboard bound to 127.0.0.1 (was *, reachable; has a Clear button) | 305c8d3 | atk → 8501 refused, local 200 |
| IMP-15 | `containment.py` docs describe tested behaviour | 3847e85 | — |
| (E11) | Bridge `fail_mode=secure` (was standalone) | 3b4bee7 | E11 below |
| — | Threat model `docs/THREAT_MODEL.md` | 7123517, 04af92e | — |

## E13 — bypass attempts while quarantined (git 997e063)

5 trials × 5 marked ICMP probes per case; "delivered" = probes seen on the target's switch port.

| Case | Delivered |
|---|---|
| C0 control, no quarantine (requests + replies) | 50/25 |
| C5a control, ARP, no quarantine | 5/25 |
| C1 attacker, own identity | 0/25 |
| C2 spoofed host IP | 0/25 |
| C3 spoofed host MAC + IP | 0/25 |
| C4 spoofed device MAC + IP, to the host | 0/25 |
| C5 attacker ARP for the twin | 0/25 |
| C6 attacker → Ryu REST / dashboard | 0/10 |

Host reached the twin during quarantine; 0 rules left after release. A first run (git b1fa61e)
showed 1/25 in every case: tcpdump writes one empty line when stopped; fixed in 997e063.

## E11 — Ryu controller failure (5 trials per case)

A: quarantine, stop Ryu, probe every second for 60 s, restart Ryu. B: isolate while Ryu is down.

| | `fail_mode=standalone` (git e7caeab) | `fail_mode=secure` (git 3b4bee7) |
|---|---|---|
| A: attacker reaches twin during outage | yes, from t = 11–13 s, 5/5 trials | 0/254 probes, 5/5 trials |
| A: host reaches twin during outage | 100% | 254/254 |
| A: our rules at 60 s | 0 of 16 (flushed) | 16 of 16 |
| A: after Ryu restart | 0 rules, attacker reaches twin | 16 rules, attacker blocked |
| B: isolate with Ryu down | ok=False, 0 rules, attacker reaches twin (5/5) | same (5/5) |

Emulator alive in every probe of both runs. An earlier run (git 997e063) was invalid: the script's
`pkill -f ryu-manager` also killed the tmux server and with it the emulator; fixed in e7caeab.
**Open (Member 2):** after a failed isolate the healing engine must keep the device marked
uncontained and retry until Ryu is back.

## E3 — capture fidelity of the mirror port (git 4e5a692)

10 s TCP SYN stream from `atk` to the twin, 3 trials per rate. Sent = OVS rx on `v-atk`, delivered =
OVS tx on `tap1_0` (both count SYNs and the attacker's RSTs to SYN-ACKs), mirror = SYNs from atk
captured on `twin-mon` with tcpdump (64 MB buffer). Means of 3 trials.

| hping3 setting | Achieved SYN rate | Sent | Delivered to twin | Mirror SYNs | Kernel drops |
|---|---|---|---|---|---|
| `-i u1000` | ≈ 570/s | 11,365 | 11,383 | 5,681 | 0 |
| `-i u100` | ≈ 2,500/s | 49,937 | 49,953 | 25,013 | 0 |
| `--flood` | ≈ 132,000/s | 1,360,377 | 49,528 | 1,323,961 | 0 |

- At the two lower rates every packet sent reached the twin, and the mirror captured every SYN
  (≈ half of the sent count, the other half being the attacker's RSTs).
- In a flood only ≈ 3.6% of sent packets reached the twin's port, while the mirror captured ≈ 97%:
  the mirror copies packets as they enter the bridge, so the monitors see the whole flood,
  including the part the twin never receives.
- The CHANGELOG note that "the mirror captured ~2–3k/s" during a 178k/s flood is therefore not a
  property of the mirror port; it most likely came from the capture software used then (scapy
  collector). Not yet measured: the scapy collector's own capture rate (needed before recording
  floods for the dataset, DAT/E1).
- An earlier run (git 04af92e) recorded 0 mirror packets: tcpdump could not write its capture file
  after dropping privileges; port counters from that run agree with the above.
