#!/usr/bin/env python3 -I
"""test_phase2c.py — the temporal features must be causal; the anomaly rule must match its definition.

  python3 -I -m pytest tests/test_phase2c.py -v
"""
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
import run_phase2c as P  # noqa: E402
from common import FEATURE_ORDER_V2  # noqa: E402


def rows(n, http=None, t0=0.0, step=5.0):
    out = []
    for i in range(n):
        f = {k: 0.0 for k in FEATURE_ORDER_V2}
        f["n_http"] = (http[i] if http else 0.0)
        f["pkt_count"] = i / 100.0
        out.append({"window_start_epoch": t0 + i * step, "window_end_epoch": t0 + i * step + 5, "features": f})
    return out


def test_temporal_features_are_causal():
    """Changing a later window must not change any earlier window's temporal features."""
    r = rows(20)
    a = P.temporal_matrix(r)
    r2 = rows(20); r2[15]["features"]["n_http"] = 1.0; r2[15]["features"]["pkt_count"] = 0.9
    b = P.temporal_matrix(r2)
    assert np.allclose(a[:15], b[:15])
    assert not np.allclose(a[15:], b[15:])


def test_temporal_features_order_independent_of_input_order():
    r = rows(10)
    shuffled = [r[i] for i in (3, 0, 9, 1, 2, 8, 4, 7, 5, 6)]
    a = P.temporal_matrix(r)
    b = P.temporal_matrix(shuffled)
    for j, i in enumerate((3, 0, 9, 1, 2, 8, 4, 7, 5, 6)):
        assert np.allclose(b[j], a[i])


def test_history_resets_after_gap():
    r = rows(6, http=[1, 1, 1, 1, 1, 1]) + rows(1, t0=10_000)        # second block after a long gap
    T = P.temporal_matrix(r)
    i_frac = P.TEMP_NAMES.index("http_active_frac_12")
    assert T[5, i_frac] == 1.0 and T[6, i_frac] == 0.0               # no carry-over across the gap


def test_periodic_beacon_has_regular_gaps():
    every3 = [1 if i % 3 == 0 else 0 for i in range(12)]
    T = P.temporal_matrix(rows(12, http=every3))
    assert T[-1, P.TEMP_NAMES.index("http_gap_std_12")] == 0.0        # perfectly periodic
    assert abs(T[-1, P.TEMP_NAMES.index("http_active_frac_12")] - 4 / 12) < 1e-9
