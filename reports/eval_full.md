# Comprehensive Evaluation Report

**Status**: PRELIMINARY — attack data from one collection session (Oct 16)
**Split method**: `runid` (run-ID-held-out)
**Threshold**: c ≥ 0.35 → malicious
**Dataset**: data/dataset_v3.jsonl (443 supervised windows)
**Model**: retrained on train split

## Split Summary

| Partition | Windows | Run IDs | Classes |
|-----------|---------|---------|--------|
| Train | 316 | 23 | {'scan': 33, 'bruteforce': 105, 'dos': 24, 'beacon': 59, 'benign': 95} |
| Test | 127 | 8 | {'scan': 12, 'bruteforce': 29, 'dos': 10, 'beacon': 13, 'benign': 63} |

## Binary Detection (attack vs benign)

| Metric | Value | 95% Wilson CI |
|--------|-------|-------------|
| Precision | 0.9583 | [0.8602, 0.9885] |
| Recall | 0.7188 | [0.5987, 0.8141] |
| F1 | 0.8214 | — |
| FPR | 0.0317 | [0.0087, 0.1086] |

**Confusion matrix**: TP=46, FP=2, FN=18, TN=61
**Test benign windows**: 63
**Test attack windows**: 64

## Per-Class Metrics (multi-class head, test attack windows)

| Class | Precision | Recall | F1 | Support | Recall 95% CI |
|-------|-----------|--------|----|---------|-------------|
| beacon | 1.0000 | 0.9231 | 0.9600 | 13 | [0.6669, 0.9863] |
| bruteforce | 1.0000 | 1.0000 | 1.0000 | 29 | [0.8830, 1.0000] |
| dos | 1.0000 | 0.9000 | 0.9474 | 10 | [0.5958, 0.9821] |
| scan | 0.8571 | 1.0000 | 0.9231 | 12 | [0.7575, 1.0000] |

## Multi-class Confusion Matrix

| true \ pred | beacon | bruteforce | dos | scan |
|---|---|---|---|---|
| **beacon** | 12 | 0 | 0 | 1 |
| **bruteforce** | 0 | 29 | 0 | 0 |
| **dos** | 0 | 0 | 9 | 1 |
| **scan** | 0 | 0 | 0 | 12 |

## Run-ID Overlap Check

**PASS**: No run_id overlap between train and test splits.

## Limitations

- All attack data from one continuous session (Oct 16, 2026)
- Run-ID split is better than random but not equivalent to independent sessions
- Benign data from two sessions (Oct 16 + Oct 19)
- Results should be treated as PRELIMINARY until validated with independently collected data
