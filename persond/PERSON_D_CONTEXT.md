# Person D — Context and Progress (as of 17 Oct 2026)

Person D's part of the IoT firmware-twin self-healing capstone: **policy engine, SDN containment,
self-healing engine, threat database, dashboard**. Everything that can be built without the twin is built
and tested on a laptop (Windows, Python 3.13) with the recordings in `samples/`, `tests/fake_restore.py`
and a fake Ryu controller. Next: first run on Sriya's twin host — see `README_TWIN_HOST.md`.

## Architecture coverage

| Diagram box | Built in | Status |
|---|---|---|
| Risk Score + Threat Label -> Policy Engine | `alert_reader.py`, `policy.py` | done |
| Policy Engine | `policy.py` (30 / 70 bands; strict 50 after an escalation) | done |
| SDN Controller -> Traffic Containment | `containment.py` (Ryu REST: drop rules, meter) | done, tested vs fake Ryu only |
| Rule Verification | `containment.py` reads the rules back from the switch | done, tested vs fake Ryu only |
| Self-Healing Engine | `healing_engine.py` (Graded, Verified Rollback) | done |
| Reinstall / Update Rule | restore command = `twin_net.sh heal` (restore + re-attach + check) | fake restore on laptop |
| Escalate Policy (+ feedback arrow) | `healing_engine.py` hold / notify; strict policy for 1 h | done |
| Update Threat Database (+ feedback arrow) | `threat_db.py`; policy reads escalation history | done |
| Dashboard | `dashboard.py` (Streamlit) | done |

## Self-healing approach: Graded, Verified Rollback

1. **Decide** risk > 70 heal, 30–70 rate-limit, < 30 watch (after an escalation: heal above 50 for 1 hour)
2. **Don't double-heal** ignore the device during a reset + 30 s; never reset if the detector already is
3. **Reset** isolate (verified drop rule) -> restore (one at a time) -> release
4. **Verify** next 3 alerts after the grace must be <= 70 -> verified; high -> reinfected; none within 2 min -> unverified
5. **Escalate**
   - *hold*: 3 heals within 10 min (counted fresh from the last human clear), or a failed reset ->
     auto-reset stopped, device stays isolated until cleared (dashboard button or `--clear`)
   - *notify*: rate-limited 2 min without returning to normal, or a containment rule not confirmed
6. **Record** everything in `threat.db`

## Files (`persond/`)

| File | What |
|---|---|
| `alert_reader.py` | reads the feed, checks the schema, passes Person A's `health` records through |
| `policy.py` | risk -> observe / rate_limit / quarantine (strict mode) |
| `threat_db.py` | SQLite: alerts (+firmware_id), actions, heals (+trigger_risk, verify_status), device_state, escalations, containment, indicators, health; old files upgraded automatically |
| `containment.py` | `print` mode (laptop) or `ryu` mode (twin host); isolate / release / rate_limit / unlimit + verification |
| `fake_ryu.py` | stand-in Ryu REST API for tests |
| `healing_engine.py` | the six steps above; `--status`, `--clear <ip>` |
| `run_pipeline.py` | whole chain: files, pipe, or `--follow logs/alerts.jsonl`; `--restore-cmd`, `--containment ryu`, `--dpid` |
| `dashboard.py` | status pill, 4 stat cards, risk timeline with bands + heals, why panel, held devices + Clear, heal history, recent actions; light + dark; refresh 2 s |
| `evaluate.py` | Person D's evaluation table from `threat.db` |
| `run_all_tests.py` | runs `test_step1` … `test_step8` + evaluation (all pass) |
| `README_TWIN_HOST.md` | checklist and commands for the first run on the twin host |

## Results on the 7 recordings

99 alerts, 7 heals (3 by our engine, 4 by the detector — no double resets), verify: 3 verified, 2 unverified,
2 pending (recordings end early), 0 escalations, 0 benign-labelled windows acted on.
Detector's real restore times in the recordings: median 73 s (63–96 s).

## Decisions taken

- Bands 30 / 70 (team class design); strict edge 50 for 1 hour after any escalation (our addition, matches the diagram's feedback arrow)
- Grace 30 s, verify 3 windows, verify deadline 2 min, hold at 3 heals / 10 min, notify after 2 min rate-limited
- Containment matches the twin's MAC (00:de:fa:1a:01:00), not a port, because the tap is recreated on every heal;
  allow rules keep 192.168.0.2 <-> twin and ARP working so the heal script can check the device
- Message bus: none (file + `--follow`); Docker: skipped

## Still open (needs the twin host or the team)

- First live run (README_TWIN_HOST.md): Ryu field names on Ryu 4.34, meter support, `BRIDGED=1` + `--alerts-only`
- Watchdog heals are not known to our engine yet; need one example `health` line from `logs/alerts.jsonl`
- True false-positive rate and detection latency need Person B's run manifest (attack times)
- Band vs detector-label mismatch: a 36–70 "malicious" window is only rate-limited
- Only report tested parts in the review report
