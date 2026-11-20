# Changelog — Phase 1 Working Copy

All changes relative to the original `iot_digital_twin/` repository.

## [Unreleased] — Phases 3–5 preparation (branch `phase3-prep`; no twin used)

Plan: `DELIVERABLE_3_PHASE3-5_PLAN.md` (approved). Steps 1–3 below need no live twin.

### Decisions recorded 2026-11-21 (before any Phase 4 session)
- **Environment ready**: `scripts/check_env.sh` on the twin VM — 60 pass, 0 fail, 2 expected warnings
  (host `ip_forward=1` with no route out of `atk`; runtime log `network/.state/ryu.log` modified).
  Twin web UI answers `GET /` with HTTP 200; OVS meters supported (max 200000, drop band, kbps).
- **Baseline registered** on the VM: `image.baseline.raw` SHA-256
  `0965f6ddf05763f77850e53181434b8bc5214a9f13f9ed0d265773b0807da2e5`
  (VM-local copy in `network/.state/baseline.sha256`, which git ignores; this line is the record).
- **Phase 3 live model (D1)**: keep `models_v3_hybrid` (xgboost.json SHA-256 prefix `0a4d261e56e7647a`).
  Phase 3 measures response mechanics; the final model is trained on the Phase 4 train sessions.
- **Session split registered (D2)**: `data/session_split.json` — train L20261016, L20261019, S01–S03, S05, S06,
  S08, S10, S11, S13, S15; val S04, S09, S14; test S07, S12, S16; spares S17, S18 (substitution rule in the file).
- **D3 (temporal beacon features)**: not added; may be evaluated later as a separately reported variant.

### Pilot S00 on the twin (2026-11-21) — kit problems found and fixed
S00 ran 8 of 13 episodes (4 benign, beacon-long 60 s, beacon, scan-slow, DoS) and stopped at the preflight
after the DoS; built, merged and validated: 309 windows, labels consistent with the episodes
(beacon 74, scan 15, DoS 5, benign 170 in 7 runs), all three monitors alive. Not yet exercised: bruteforce,
full scan, final heal. Observed: hping sent ~178k packets/s, the mirror captured ~2–3k/s (flood heavily
under-sampled by the network monitor — threats to validity). Fixes:
- **Self-healing watchdog** restored the twin at the start of a first S00 attempt; during collection it
  would restore the twin mid-DoS. Collection now runs without it (`NOWATCHDOG=1`); preflight refuses a
  healing watchdog (`kit.py watchdog-healing`).
- **Readiness**: one 2-s ping right after the DoS was lost although the twin was alive (same emulator
  process throughout). Preflight now waits up to 120 s for ping + HTTP and logs the wait.
- `build_dataset.sh`: relative raw/out paths broke after `cd stream/`; now absolute. Skips empty raw files
  (left by `record.sh` when stopped) and files not captured on `twin-mon` (excludes Oct 3 by default).
- `merge_sessions.py`: legacy sessions only before 2026-11-01 UTC (a recorder started 9 s early produced a
  bogus `L20261120`); pilot session files (`P*.json`) are read.
- Pilot IDs `P01`–`P99`; the split loader rejects them. `run_protocol.sh` keeps sudo authorised.
- On the VM, discarded files are kept in `data/raw_discarded/` and `data/sessions_discarded/` with a README.

### Corrections found in this review (disclosed)
- **Collection kit captured on the wrong interface.** `record.sh` defaults to `tap1_0.1`, and the Phase 2
  `COLLECTION_PROTOCOL.md` said so; the Oct 16/19 training data were captured on the mirror `twin-mon`
  (Oct 3 on `tap1_0.1` — another cause of the Oct 3 shift). The kit now refuses to run unless the
  recorder captures on `twin-mon`.
- `split_by_session()` was described in `split_utils.py` (Phase 1) but not implemented. Now implemented.
- `collect_session.sh` preflight: `ip netns list | grep -q` under `set -o pipefail` could fail at random
  (grep exits early, the writer gets SIGPIPE). Fixed; found by the new end-to-end kit test.
- `threat_model_v3.py`: comment said 95th percentile, code uses the 99th (comment only; no behaviour change).

### Added — step 1 (collection)
- `scripts/check_env.sh` — read-only readiness check (PASS/WARN/FAIL/SKIP, `--json`). Checks HTTP only when the
  twin answers ping, so a proxy cannot answer for it.
- `scripts/kit.py` — recorder-interface check, session metadata files, beacon period rotation
- `scripts/merge_sessions.py` — `session_id` per window from `data/sessions/*.json`; legacy data → `L<date>`
- `data/session_split.template.json` — proposed 10 / 3 / 3 split + spares (**not registered**)
- `collect_session.sh` scenarios: `benign-burst`, `benign-idle`, `beacon-long` (10/30/60 s ± 20%, 300 s).
  `benign-login` from the plan was replaced by `benign-burst`: the bruteforce scenario never performs a
  real login (basic-auth GETs on `/`), so the realistic hard negative is a browser's request burst.
- `run_protocol.sh`: `SESSION_ID` required; writes `data/sessions/<id>.json`; marks aborted sessions
- `split_utils.py`: `load_session_split()`, `split_by_session()`, `session_ids_of()`

### Added — step 2 (offline analyses, `experiments/run_phase2b.py`, reports in `reports/phase2b/`)
- C11 risk-score analysis and data-based reinfection threshold; EXP-2 latency with held-out models
  (supersedes `reports/latency_fp.md`); EXP-11 label boundaries; EXP-8 θ × weight grid + heatmap;
  C4 KitNET-style baseline on window features

### Added — step 3 (recovery verification)
- `persond/verify_heal.py` — independent read-only heal checks: baseline-image hash vs a registered
  hash, boot (ping ≤ 60 s), service (HTTP ≤ 90 s), no containment rules left, optional client command.
  Deviation from the plan: the running `image.raw` is not hashed, because `restore.sh` boots it before
  the engine regains control and the firmware writes to it; that needs a hook inside `restore.sh`.
- `healing_engine.py`: optional `verifier`; a heal is `verified` only if the windows are calm **and**
  no check failed, else `unverified` + operator notification. Default (no verifier) unchanged.
- `threat_db.py`: additive table `heal_checks`. `run_pipeline.py`: `--verify windows|full`,
  `--accept-http`, `--client-cmd` (default `windows` = previous behaviour)

### Tests
- `tests/test_collection_kit.py` (real scripts with stub system commands, full protocol run),
  `tests/test_sessions.py`, `tests/test_phase2b.py`, `tests/test_verify_heal.py`;
  existing `persond/run_all_tests.py` still passes

## Phase 2

### Corrections to Phase 1 (disclosed)
- `reconstruct_oct3.py` (Phase 1) wrote RAW unscaled values (e.g. `pkt_count` up to 897) into
  `features`, while dataset_v3 is min-max scaled; the report wrongly called it "fully compatible".
  Rewritten to scale with the frozen `data/scaler_v3.json` via `stream/pipeline.apply_scaler`.
- Phase 1 said the Oct 3 sessions had no labels. `data/run_manifest.jsonl` does label them
  (1 benign, 9 nmap scan, 3 healing runs). Now labelled with `stream/pipeline.Labeler`; the scan
  class is inferred from the recorded command and marked `attack_class_source=inferred_from_manifest_command`.

### Added
- `scripts/collect_session.sh` — one labelled episode via the existing `stream/label_run.py`
  (same commands as Oct 16 + a low-volume `scan-slow`); preflight checks incl. no default route in `atk`
- `scripts/run_protocol.sh` — one full independent session (shuffled attack order, benign between attacks, heal)
- `scripts/build_dataset.sh` — builds one dataset from all raw sessions, then validates
- `scripts/validate_session.py` — schema/timing/monitor-alive/label/episode-count checks
- `scripts/COLLECTION_PROTOCOL.md` — environment, safety, independence rules, outputs
- `experiments/core.py` — shared splits (primary, repeated grouped, Oct 3 cross-session), 10 detectors, metrics
- `experiments/run_phase2.py` — EXP-3, 4, 5, 6, 8, 9, 10
- `experiments/shift_oct3.py` — EXP-6b diagnostic of the Oct 3 false alarms
- `tests/test_phase2.py` — 12 tests (engine reproduces Phase 1 confusion matrix exactly; benign-only
  detectors fitted on benign rows only; Oct 3 rebuild scaled + labelled; validator; script syntax)

### Reports
- `reports/phase2/*.md|json` — all generated by the scripts above

## Phase 1

### Added
- `CHANGELOG.md` — this file
- `split_utils.py` — run-ID-held-out and session-held-out splitting (C1). No random shuffling of windows across splits. Entire run_ids kept together.
- `eval_full.py` — comprehensive evaluation with Wilson 95% CIs, per-class metrics, confusion matrix (C2)
- `dataset_audit.py` — full dataset audit: class distribution, session mapping, feature variance
- `reconstruct_oct3.py` — Oct 3 raw data reconstruction (kept UNLABELLED)
- `tests/test_phase1.py` — 13 unit tests for all Phase 1 code

### Modified
- `common.py` — added `ZERO_VARIANCE_FEATURES` list (8 features), `effective_features()` function (C3)

### Reports Generated
- `reports/dataset_audit.md` — 783 windows, 443 supervised, 37 effective features
- `reports/dataset_audit.json` — machine-readable audit
- `reports/oct3_reconstruction.md` — 261 windows reconstructed, all unlabelled
- `reports/eval_full.md` — PRELIMINARY corrected metrics with run-ID split
- `reports/eval_full.json` — machine-readable results
- `data/dataset_oct3_reconstructed.jsonl` — 261 Oct 3 windows (unlabelled)

### Key Finding
- **Corrected metrics (run-ID split)**: F1=0.821, Recall=0.719, Precision=0.958, FPR=0.032
- **Previous (leaked random split)**: F1=0.864, FPR=0.053
- Confirms random split was inflating recall by ~18 percentage points
