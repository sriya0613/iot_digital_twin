# Oct 3 Raw Data Reconstruction Assessment

**Total raw files**: 6
**Total windows**: 261
**Successfully reconstructed**: 261
**Output**: `data/dataset_oct3_reconstructed.jsonl`

**IMPORTANT**: All reconstructed records are labelled `unlabeled`.
Do NOT relabel as benign without confirmation from the original collector.

## Per-file Summary

| File | Windows | Compatible |
|------|---------|----------|
| `session_20261003T095216.jsonl` | 123 | 123 |
| `session_20261003T102309.jsonl` | 46 | 46 |
| `session_20261003T102718.jsonl` | 41 | 41 |
| `session_20261003T103100.jsonl` | 49 | 49 |
| `session_20261003T103513.jsonl` | 2 | 2 |
| `session_20261003T103529.jsonl` | 0 | 0 |

## Feature Compatibility

**All Oct 3 windows contain all 45 FEATURE_ORDER_V2 features.** Reconstruction is fully compatible.

## Next Steps

1. Confirm with original collector whether Oct 3 sessions were benign-only
2. If confirmed benign, relabel with `label_session.py`
3. Use as additional benign data for FPR estimation (from an independent date)
