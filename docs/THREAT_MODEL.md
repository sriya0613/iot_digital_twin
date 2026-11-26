# Threat model

Scope of the security claims made for the firmware digital twin (detection, SDN containment,
verified self-healing). Written for the paper's new Section III; every "holds" below points to a
test, every "not claimed" is stated as a limitation.

## System and trust boundaries

| Component | Where | Trusted? |
|---|---|---|
| Twin firmware (D-Link DIR-868L 2.05b02, FirmAE/QEMU) | `tap1_0` on `br-twin`, 192.168.0.1 | **No** — this is what gets compromised |
| Twin host (restore, verifier, detector, healing engine, dashboard) | VM, `twin-host` 192.168.0.2 | Yes |
| Open vSwitch `br-twin` and Ryu controller | VM | Yes |
| Clean baseline image | VM disk | Yes (integrity assumed, see A3) |
| Other LAN hosts (`atk` 192.168.0.10, `cli` 192.168.0.20) | network namespaces on `br-twin` | No |

Trust boundary: the bridge. Everything attached to `br-twin` except `twin-host` is untrusted.

## Adversary

- **Position:** a host on the same LAN segment as the device (modelled by the `atk` namespace).
  Can send arbitrary Ethernet frames on its own port: any source MAC/IP, ARP, broadcasts.
- **Goals:** (G1) compromise the device; (G2) keep or regain access to it after detection;
  (G3) disable or undo the response (delete quarantine rules, clear a hold, stop a heal);
  (G4) use the device to reach other hosts.
- **Attacks evaluated:** port scan, SYN flood, credential brute force, periodic inbound requests
  ("beacon"). No real malware sample.

## Assumptions

- A1. The VM host, its OS and the hypervisor are not compromised.
- A2. The attacker has no shell or credentials on the VM.
- A3. The clean baseline image is correct and unmodified.
- A4. OVS and Ryu behave as specified (OpenFlow 1.3, highest-priority match wins).
- A5. The emulated firmware behaves like the device for the attacks above (fidelity limits:
  experiments E3, E16).

## Security properties and how they are checked

| # | Property | Mechanism | Evidence | Status |
|---|---|---|---|---|
| P1 | While quarantined, only the twin host reaches the device | MAC drops (prio 200); MAC+IP allow pinned to `twin-host` port (300); ARP limited (250/300) | `tests/test_containment.py`; live 2026-11-26: host 3/3, atk 0/3 | Holds (non-spoofed) |
| P2 | An attacker cannot pose as the host or the device to pass the quarantine | Anti-spoof drops: host MAC only from `twin-host`, device MAC only from the tap (prio 400) | Unit tests (spoofed MAC/IP/ARP dropped) | Live test pending (E13) |
| P3 | Installed rules are the intended rules | Read-back compares priority, match, actions per rule | Unit tests (wrong/missing rule → not verified); live verified=True | Holds |
| P4 | The attacker cannot change the response through the control plane | Ryu REST and dashboard bound to 127.0.0.1 | Live 2026-11-26: atk → 8080 and 8501 refused | Holds |
| P5 | A heal returns the device to the clean baseline | Restore from baseline + independent verifier | Phase 3 T1 (3/3) | Partial — verifier hashes the baseline, not the live disk (IMP-05); release before verify (IMP-06) |
| P6 | A failed heal leaves the device contained | Verify before release | — | Not yet (IMP-06/08, Member 2) |
| P7 | Containment survives controller loss | OVS keeps installed flows; `fail_mode=standalone` | — | To measure (E11) |

## Not claimed (out of scope)

- Escape from QEMU to the VM, or any attack on the VM itself (A1, A2).
- Attacks wholly inside the 90 s post-heal grace period (no response is triggered).
- Attacks the detector does not flag (slow scans and beaconing have low recall); containment only
  starts after a detection.
- Zero-day or real-malware detection; only the four attack types above were evaluated.
- Physical devices; results are for the emulated twin.
- After a heal the twin's tap gets a new switch port with no anti-spoof rule until the next
  isolation; the device (not the attacker) could then send with the host's MAC.

## Open items that change this document

IMP-05, IMP-06, IMP-08 (Member 2) for P5–P6; E11 for P7; E13 for P2.
