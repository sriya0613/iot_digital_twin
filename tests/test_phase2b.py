#!/usr/bin/env python3 -I
"""test_phase2b.py — checks for experiments/run_phase2b.py.

  python3 -I -m pytest tests/test_phase2b.py -v
"""
import json
import os
import sys

import numpy as np
import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
import core  # noqa: E402
import run_phase2b as P  # noqa: E402
from threat_model_v3 import HybridModel  # noqa: E402

HAVE_V3 = os.path.exists(core.DATA_V3)


@pytest.mark.skipif(not HAVE_V3, reason="dataset_v3 not present")
def test_vectorised_risk_equals_assess():
    """The batch risk used in every Phase 2b table must equal HybridModel.assess() window by window."""
    d = core.load_v3()
    tr, te = core.primary_split(d)
    hm = HybridModel().fit(d.X[tr], d.y[tr], d.c[tr])
    conf, anom, sev = P.risk_parts(hm, d.X[te])
    fast = P.blended(conf, anom, sev)
    slow = np.array([hm.assess(x, explain=False)["risk_score"] for x in d.X[te]])
    assert (fast == slow).all()
    assert set(fast) - {0} and fast.max() > 70          # non-trivial: real attacks reach quarantine


def test_blended_weights_match_deployed_formula():
    r = P.blended(np.array([0.8]), np.array([0.5]), np.array([0.9]))
    assert r[0] == round(100 * (0.5 * 0.8 + 0.2 * 0.5 + 0.3 * 0.9 * 0.8))
    assert P.blended(np.array([0.0]), np.array([1.0]), np.array([0.9]))[0] == 20   # anomaly alone caps at 20


@pytest.mark.parametrize("scores,thr,k,want", [
    ([90, 90], 80, 2, True), ([90, 10, 90], 80, 2, False), ([80, 80], 80, 2, False),
    ([10, 85, 86, 10], 80, 2, True), ([], 80, 2, False), ([81], 80, 1, True)])
def test_streak_rule_matches_healing_engine(scores, thr, k, want):
    assert P.streak_hit(scores, thr, k) is want        # strictly greater than thr, k in a row


def test_kitnet_style_uses_only_benign_and_scores_outliers_high():
    rng = np.random.RandomState(0)
    base = rng.rand(300, 3)
    Xb = np.column_stack([base, base * 0.5 + 0.01 * rng.rand(300, 3), rng.rand(300, 2) * 0.1])   # correlated groups
    k = P.KitNETStyle(m=4).fit(Xb)
    assert all(len(g) <= 4 for g in k.groups)
    assert sorted(i for g in k.groups for i in g) == list(range(8))
    s_ben = k.score(Xb)
    assert np.mean(s_ben >= 1.0) <= 0.02                # ~1% of training benign above the 99th pct
    out = Xb[:20].copy(); out[:, 3:6] = 1.0 - out[:, 3:6]  # break the learned correlation
    assert np.median(k.score(out)) > np.median(s_ben)


@pytest.mark.skipif(not HAVE_V3, reason="dataset_v3 not present")
def test_kitnet_fit_only_sees_benign(monkeypatch):
    seen = {}
    orig = P.KitNETStyle.fit

    def spy(self, Xb):
        seen["n"] = len(Xb); return orig(self, Xb)
    monkeypatch.setattr(P.KitNETStyle, "fit", spy)
    d = core.load_v3()
    tr, te = core.primary_split(d)
    P._kitnet_fit(d.X[tr], d.y[tr], d.c[tr], None)
    assert seen["n"] == int((d.y[tr] == 0).sum())


@pytest.mark.skipif(not HAVE_V3, reason="dataset_v3 not present")
def test_supervised_windows_are_time_ordered_within_runs():
    last = {}
    for l in open(core.DATA_V3):
        r = json.loads(l)
        if r["label"] in ("benign", "malware"):
            assert r["window_start_epoch"] >= last.get(r["run_id"], -1)
            last[r["run_id"]] = r["window_start_epoch"]
