# Member 2 — healing, verification and failure tests, 2026-11-26/27

All live runs on Member 2's copy of the twin VM (FirmAE D-Link DIR-868L 2.05b02, OVS `br-twin`,
`fail_mode=secure`, Ryu 4.34, VirtualBox 4 GB RAM), branch `phase3-prep`, main watchdog paused.
Scripts: `experiments/member2/`. Raw logs and per-trial CSVs are on that VM under `reports/member2/`.
Task IDs as in the four-person task split. Restores use FirmAE's own `restore.sh` (see "Problems found").

## Code changes

| ID | Change | Commit |
|---|---|---|
| IMP-06 | With `--verify full`, baseline / disk / boot / service are checked while the twin is still isolated; it is released only if they pass, else it stays isolated and is held. Network / client checks after release; a failure isolates it again and holds it. | 3fb2aff |
| IMP-08 | A reinfection verdict isolates again and holds (was only recorded); one high window while verifying no longer starts a second restore before the two-in-a-row rule decides. | 3fb2aff |
| IMP-09 | Watchdog `heal_ok`/`heal_failed` records are stored as heals and count toward 3 heals in 10 min. | 3fb2aff |
| E11 follow-up | A failed isolate (Ryu down) is tried 3x, a human is notified, and it is retried on every later record. | 3fb2aff |
| IMP-11 / SYS-07 | A running restore is recorded in `threat.db`; a new engine holds a device whose restore was interrupted and isolates every held device again; stopping the engine never lifts a quarantine. | 1d12634 |
| IMP-05 (v2) | `twin_net.sh heal` records whether `image.raw` got a new inode (restore.sh replaced it with a copy of the baseline); verifier check `disk`. Metadata only, after the twin is up. | de020c9 |
| IMP-10 | `--background-restore`: restore and the checks done while isolated run in a worker thread; alerts keep being decided. Default unchanged (foreground). | 198382f, b422deb |
| IMP-18 | Unit tests for the failure paths (34 in `tests/test_verify_heal.py`, incl. restore failing mid-copy, interrupted restore, failed isolate, background restore). | several |
| (IMP-01 follow-up) | Quarantine identifies the host by its `twin-host` switch port, not its MAC (the MAC changes on every restore). Quarantine is now 12 rules. | af2ee3b |

## Live results

| ID | Test | Result |
|---|---|---|
| IMP-11 / SYS-07 | `imp11_check.sh`: engine stopped (Ctrl-C) and crashed (SIGKILL) during a restore, restarted, calm alerts | Before fix: Ctrl-C released the quarantine (attacker reached the twin); a restarted engine did not know the twin was isolated. After fix (1d12634): rules kept and attacker blocked in every state; the new engine held the twin. |
| E11 follow-up | `isolate_retry_check.sh`: Ryu stopped, high-risk alert, Ryu started | Isolate failed with Ryu down, human notified (1); quarantine installed by the engine 6 s after Ryu returned; kept after the engine stopped. |
| IMP-05, IMP-06, IMP-08 | `engine_loop_check.sh` (two real restores) | P: `restored`, checks baseline/disk/boot/service/network/client all passed, released; attacker 0/22 samples while isolated. F (service forced to fail): `restored_checks_failed`, held "heal checks failed before release: service", still 12 rules and attacker blocked after the engine exited; attacker 0/20 samples. |
| IMP-05 | record after the last E6 restore | `image.raw` inode 3413507 → 3413511, `replaced: true`, restore rc 0, restore 73 s; verifier `disk` ok. |
| IMP-09 | `imp09_watchdog_check.sh`: emulator stopped 3x, watchdog restores it | Engine stored 3 watchdog heals; on the 3rd: held "3 heals within 10 min (incl. watchdog)", 12 rules, attacker blocked. |
| IMP-10 | `imp10_background_check.sh`: alert for another device 10 s into a real restore | Foreground: decided after 85.1 s (229 s in an earlier run). Background: 0.2 s. Both restores recorded (heals 1 ok=1); no release before the restore ended. |
| SYS-01 / E6 | `e6_compromise_removal.sh 10`: file in /etc, line appended to /etc/profile, startup script in /etc/init0.d (writes a marker when it runs at boot), planted on the stopped twin's disk | Control (boot without rollback): file/modify/autorun/ran = 1 1 1 1 (persistent, and it runs at boot). 10 trials after a heal: 0 0 0 0 in 10/10; 0 failed heals; ~2.5 min per trial. |
| SYS-08 / E12 | `e12_restore_faults.sh 5`: through the engine | corrupt (boot a damaged copy of the baseline) 5/5, slow (heal given 20 s) 5/5, hung (QEMU frozen at start) 5/5: every trial `restore_failed`, held, 12 rules after the engine exited, attacker blocked. Failed restore ~205 s (corrupt, hung) or ~25 s (slow); recovery ~80-90 s. |

Notes on E12: two trial durations (corrupt 4: 2412 s, hung 4: 30951 s) include the laptop sleeping and are
not restore times; their outcomes are valid. In the first hung run, trial 5 froze a short-lived
`pkill/pgrep -f qemu-system-` command instead of QEMU (the fault was not injected; the twin booted and the
engine correctly released it); the freezer now matches the process name (4a417d5) and the hung fault was
re-run: 5/5.

## Problems found and fixed during the runs

- **Quarantine blocked the host during a restore** (engine loop, first run): `twin-host` gets a new MAC on
  every restore, and the IMP-01 allow rules pinned the old MAC, so restore.sh never saw the twin answer.
  Fixed in af2ee3b (host identified by switch port).
- **IMP-05 v1 broke booting**: `network/restore_verified.sh` (restore.sh + SHA-256 of the disk between copy
  and boot) made FirmAE's boot fail ("umount .../scratch/1/image: target is busy", no emulator) on this VM;
  with the same code restore.sh booted 3/3 (tests A/B). Default reverted to restore.sh (c10f831); v1 kept as
  opt-in; IMP-05 redone with the inode record (v2). Cause not understood.
- **Background restore released the twin mid-restore** (first IMP-10 run): the restoring twin's next alert
  was taken as a human clear. Fixed in b422deb.
- **Watchdog restarts a healthy twin whose web UI is slow** (this VM: web page 2-3 min after the first
  ping, watchdog allows ~45 s). Main watchdog paused for all tests; a fix (5-min allowance for a missing web
  page only) is set aside, not committed, pending a team decision.
- **An interrupted restore leaves FirmAE's disk mount behind**, so the next boot fails once; `heal`'s retry
  recovers. Test scripts now stop leftover restore/FirmAE processes before recovering.

## Waiting on Member 4

IMP-07 (new "clean after heal" rule), SYS-06 (verification behaviour) and E10 (re-attack 10/30/60 s after a
heal) need the benign post-heal threshold from the retrained model. Doing them with the current model would
have to be redone after retraining.
