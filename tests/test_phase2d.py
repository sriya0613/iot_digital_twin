#!/usr/bin/env python3 -I
"""test_phase2d.py — in-split scaling must use training rows only; metrics must match their definitions.

  python3 -I -m pytest tests/test_phase2d.py -v
"""
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
import run_phase2d as P  # noqa: E402


def test_raw_round_trip():
    import json
    d = P.C.load_v3()
    raw = P.raw_from_global(d.X)
    rng = json.load(open(P.SCALER))["ranges"]
    lo = np.array([rng[k][0] for k in P.FEATURE_ORDER_V2]); hi = np.array([rng[k][1] for k in P.FEATURE_ORDER_V2])
    span = np.where(hi > lo, hi - lo, 1.0)
    assert np.allclose((raw - lo) / span, d.X, atol=1e-9)        # exact inverse of the stored scaling
    assert np.all(raw >= lo - 1e-9) and np.all(raw <= hi + 1e-9)  # stored data were never clipped


def test_rescale_uses_training_rows_only():
    raw = np.array([[0.0, 5.0], [10.0, 5.0], [20.0, 5.0], [100.0, 5.0]])
    tr = np.array([0, 1, 2])
    Z = P.rescale(raw, tr)
    assert np.allclose(Z[:3, 0], [0.0, 0.5, 1.0])
    assert Z[3, 0] == 1.0                       # test value above the training max is clipped
    assert np.all(Z[:, 1] == 0.0)               # constant in training -> 0


def test_mcc_and_balanced_accuracy():
    y = np.array([1, 1, 0, 0]); s = np.array([1.0, 0.0, 0.0, 0.0])
    m = P.full_metrics(y, s, 0.5, np.array(["dos", "dos", "benign", "benign"], dtype=object))
    assert abs(m["mcc"] - (1 * 2 - 0) / np.sqrt(1 * 2 * 3 * 2)) < 1e-12
    assert abs(m["bal_acc"] - 0.75) < 1e-12


def test_trivial_flag_all():
    y = np.array([1] * 64 + [0] * 36)
    m = P.full_metrics(y, np.ones(100), 0.5, np.array(["dos"] * 64 + ["benign"] * 36, dtype=object))
    assert m["recall"] == 1.0 and m["fpr"] == 1.0 and m["mcc"] == 0.0
    assert abs(m["f1"] - 2 * 0.64 / 1.64) < 1e-12
