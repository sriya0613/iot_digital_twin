# Changelog — Phase 1 Working Copy

All changes relative to the original `iot_digital_twin/` repository.

## [Unreleased]

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
