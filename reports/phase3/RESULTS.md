# Phase 3 — Live containment and recovery (EXP-7, EXP-12)

Run on 2026-11-21 on the VM twin (DIR-868L, FirmAE), branch phase3-prep. All raw logs and the
threat database are in `raw/`. Every number below comes from those files; nothing was simulated.
Attacks were scripted (hping3 SYN flood, curl brute force), not real malware.

## T1 — Clean restore + independent verification (n = 3)

| Run | Restore (twin answers ping) | Web UI HTTP 200 after ping | All 5 checks |
|---|---|---|---|
| 1 | 118 s | +41.8 s | pass |
| 2 | 97 s | +77.6 s | pass |
| 3 | 81 s | +65.2 s | pass |

Checks: baseline SHA-256 (0965f6dd… = registered), boot, service, no containment rules left, client ping.
Full service recovery (restore + web UI) = 159.8 / 174.6 / 146.2 s; the paper's ~75 s figure is not supported.

## T2 — Quarantine (isolate) on the switch (n = 3)

- Isolate rule installed and read back: 0.047 / 0.038 / 0.042 s (median 0.042 s).
- Release: 0.018 / 0.021 / 0.023 s.
- During quarantine: attacker 200/200 pings lost and HTTP 000; client 5/5 lost (whole device isolated, by design);
  host restore-check exception 5/5 replies. Drop rule counter: 208 packets.
- After release: attacker 3/3 replies; no rules left.

## T3 — Rate limit (OVS meter, 1000 kbit/s), 10 s SYN flood (n = 3)

| Run | Delivered without meter | Delivered with meter |
|---|---|---|
| 1 | 29,694 | 22,324 |
| 2 | 56,193 | 27,038 |
| 3 | 54,977 | 24,646 |

Mean reduction ≈ 47% (consistent with a 1000 kbit/s cap ≈ 2,100 SYN/s). Meter install 0.031–0.048 s; no rules left.

## T4 — Full live loop (detector → policy → containment → heal → verify)

| Event | Attack start (UTC) | Action | Containment | Restore | Verify |
|---|---|---|---|---|---|
| DoS | 18:27:42.6 | quarantine at risk 96, 18:27:48.3 (≈5.7 s after start) | 0.083 s | 108.95 s | verified |
| Brute force | 18:32:27.0 | rate-limit at risk 51 (18:32:28), then quarantine at risk 76 (18:32:33, ≈6 s) | 0.043 / 0.076 s | 106.80 s | verified |
| Third DoS | 18:37:11.0 | quarantine at risk 89 (18:37:13.3, ≈2.3 s) | 0.082 s | 109.51 s | pending → ESCALATE hold (3 heals in 10 min) |

- 7/7 containment steps verified on the switch; median decision delay 0.18 s (n = 174).
- Grace period: boot windows inside the 90 s grace reached risk 40 / 74 / 22 and were correctly ignored.
- After grace, until the next attack: max risk 16 / 16 / 49; no window ≥ 50 (so none ≥ 80). This confirms
  live the offline finding that post-grace windows stay below 50.

## What was NOT shown (state in the paper)

1. **Reinfection within verification was not tested as designed.** The "reinfect" attack began ≈171 s after heal 2
   finished, after verification. It was handled as a new attack; it tested the escalation rule, which worked.
2. "0 of 169 benign windows acted on" uses the detector's own labels, not independent ground truth.
3. EXP-12d (controller loss) was not run.
4. An attack that lies wholly inside the 90 s grace period would not trigger a response.
5. n = 3 per test, one firmware image, one host.
