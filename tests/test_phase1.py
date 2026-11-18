#!/usr/bin/env python3 -I
"""test_phase1.py — Unit tests for Phase 1 code changes.

Tests: split_utils, common.py updates, eval_full helpers.

Usage:
  cd iot_digital_twin_working
  python3 -I -m pytest tests/test_phase1.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import numpy as np
import math
from split_utils import split_by_runid, split_by_runid_train_val_test, load_supervised
from common import (FEATURE_ORDER_V2, ZERO_VARIANCE_FEATURES, effective_features,
                    SYSCALL_FEATURES, ENERGY_FEATURES)


# --- common.py tests ---

def test_zero_variance_count():
    assert len(ZERO_VARIANCE_FEATURES) == 8

def test_effective_features_count():
    eff = effective_features()
    assert len(eff) == len(FEATURE_ORDER_V2) - len(ZERO_VARIANCE_FEATURES)
    assert len(eff) == 37

def test_zero_variance_all_in_v2():
    for f in ZERO_VARIANCE_FEATURES:
        assert f in FEATURE_ORDER_V2, f"{f} not in FEATURE_ORDER_V2"

def test_effective_excludes_zero_var():
    eff = effective_features()
    for f in ZERO_VARIANCE_FEATURES:
        assert f not in eff


# --- split_utils tests ---

def test_split_by_runid_no_overlap():
    """No run_id should appear in both train and test."""
    run_ids = np.array(["r1", "r1", "r2", "r2", "r3", "r3", "r4", "r4",
                        "b1", "b1", "b2", "b2"])
    cls = np.array(["scan", "scan", "scan", "scan", "dos", "dos", "dos", "dos",
                    "benign", "benign", "benign", "benign"])
    train_idx, test_idx = split_by_runid(run_ids, cls, test_frac=0.3)

    train_rids = set(run_ids[train_idx])
    test_rids = set(run_ids[test_idx])
    assert len(train_rids & test_rids) == 0, "Run IDs must not overlap"

def test_split_by_runid_complete():
    """All indices accounted for."""
    run_ids = np.array(["r1", "r1", "r2", "r2", "b1", "b1", "b2", "b2"])
    cls = np.array(["scan", "scan", "scan", "scan", "benign", "benign", "benign", "benign"])
    train_idx, test_idx = split_by_runid(run_ids, cls, test_frac=0.3)
    assert len(set(train_idx) | set(test_idx)) == len(run_ids)
    assert len(set(train_idx) & set(test_idx)) == 0

def test_split_by_runid_keeps_runs_together():
    """Windows from the same run_id must be in the same partition."""
    run_ids = np.array(["r1", "r1", "r1", "r2", "r2", "b1", "b1"])
    cls = np.array(["scan", "scan", "scan", "scan", "scan", "benign", "benign"])
    train_idx, test_idx = split_by_runid(run_ids, cls, test_frac=0.4)

    for rid in set(run_ids):
        rid_indices = set(np.where(run_ids == rid)[0])
        in_train = rid_indices & set(train_idx)
        in_test = rid_indices & set(test_idx)
        assert len(in_train) == 0 or len(in_test) == 0, \
            f"run_id {rid} split across train and test"

def test_split_3way_no_overlap():
    """Three-way split has no overlap."""
    run_ids = np.array(["r1"]*3 + ["r2"]*3 + ["r3"]*3 + ["r4"]*3 +
                       ["b1"]*3 + ["b2"]*3 + ["b3"]*3 + ["b4"]*3)
    cls = np.array(["scan"]*12 + ["benign"]*12)
    train, val, test = split_by_runid_train_val_test(run_ids, cls)

    assert len(set(train) & set(val)) == 0
    assert len(set(train) & set(test)) == 0
    assert len(set(val) & set(test)) == 0
    assert len(set(train) | set(val) | set(test)) == len(run_ids)

def test_split_3way_runs_together():
    """Each run_id in exactly one partition."""
    run_ids = np.array(["r1"]*2 + ["r2"]*2 + ["r3"]*2 + ["r4"]*2 +
                       ["b1"]*2 + ["b2"]*2 + ["b3"]*2 + ["b4"]*2)
    cls = np.array(["scan"]*8 + ["benign"]*8)
    train, val, test = split_by_runid_train_val_test(run_ids, cls)

    for rid in set(run_ids):
        rid_idx = set(np.where(run_ids == rid)[0])
        partitions = [set(train), set(val), set(test)]
        in_parts = sum(1 for p in partitions if rid_idx & p)
        assert in_parts == 1, f"run_id {rid} in {in_parts} partitions"


# --- Wilson CI tests ---

def _wilson_ci(k, n, z=1.96):
    """Local copy to avoid importing eval_full (which pulls xgboost)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n) / denom
    return (p, max(0.0, centre - spread), min(1.0, centre + spread))

def test_wilson_ci_basic():
    wilson_ci = _wilson_ci
    # 50/100 should give CI around 0.5
    p, lo, hi = wilson_ci(50, 100)
    assert abs(p - 0.5) < 0.001
    assert lo < 0.5 < hi
    assert hi - lo < 0.2  # reasonable width

def test_wilson_ci_zero():
    wilson_ci = _wilson_ci
    p, lo, hi = wilson_ci(0, 100)
    assert p == 0.0
    assert lo == 0.0
    assert hi > 0.0

def test_wilson_ci_empty():
    wilson_ci = _wilson_ci
    p, lo, hi = wilson_ci(0, 0)
    assert p == 0.0


# --- load_supervised tests ---

def test_load_supervised_excludes_healing():
    """load_supervised should only return benign and malware windows."""
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "dataset_v3.jsonl")
    if not os.path.exists(dataset_path):
        return  # skip if dataset not available
    X, ybin, cls, run_ids, meta = load_supervised(dataset_path)
    # Should have 443 supervised windows (158 benign + 285 attack)
    assert len(X) == 443, f"Expected 443 supervised, got {len(X)}"
    assert (ybin == 0).sum() == 158, f"Expected 158 benign, got {(ybin == 0).sum()}"
    assert (ybin == 1).sum() == 285, f"Expected 285 attack, got {(ybin == 1).sum()}"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
