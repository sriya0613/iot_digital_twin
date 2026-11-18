#!/usr/bin/env python3 -I
"""test_phase2.py — tests for the Phase 2 experiment engine, collection validator and Oct 3 rebuild.

  python3 -I -m pytest tests/test_phase2.py -v
"""
import json
import os
import subprocess
import sys

import numpy as np
import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import core  # noqa: E402
from common import FEATURE_ORDER_V2  # noqa: E402
from validate_session import validate  # noqa: E402

HAVE_V3 = os.path.exists(core.DATA_V3)


# ---------------------------------------------------------------- metrics
def test_metrics_counts_and_f1():
    y = np.array([1, 1, 1, 0, 0, 0])
    p = np.array([1, 1, 0, 1, 0, 0], bool)
    m = core.metrics(y, p)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 2)
    assert abs(m["f1"] - 2 / 3) < 1e-9
    assert m["precision_ci"][0] <= m["precision"] <= m["precision_ci"][1]


def test_metrics_episode_level():
    y = np.array([1, 1, 1, 1, 0])
    p = np.array([0, 1, 0, 0, 0], bool)
    r = np.array(["a", "a", "b", "b", "z"])
    m = core.metrics(y, p, runs=r)
    assert m["episodes"] == 2 and m["episodes_detected"] == 1


def test_wilson_bounds():
    p, lo, hi = core.wilson(0, 63)
    assert p == 0 and lo == 0 and 0 < hi < 0.07   # 0/63 -> upper bound ~5.7%


# ----------------------------------------------------------------- splits
def _toy():
    r = np.array(sum([[f"s{i}"] * 3 for i in range(5)] + [[f"b{i}"] * 3 for i in range(4)], []), dtype=object)
    c = np.array(["scan"] * 15 + ["benign"] * 12, dtype=object)
    y = (c != "benign").astype(int)
    return core.Data(np.zeros((len(r), 1)), y, c, r)


def test_grouped_split_keeps_runs_whole_and_covers_classes():
    d = _toy()
    for seed in range(10):
        tr, te = core.grouped_split(d, seed)
        assert not set(d.r[tr]) & set(d.r[te])
        assert set(tr) | set(te) == set(range(len(d.r)))
        for cls in ("scan", "benign"):
            assert (d.c[tr] == cls).any() and (d.c[te] == cls).any()


def test_grouped_split_varies_with_seed():
    d = _toy()
    tests = {tuple(core.grouped_split(d, s)[1]) for s in range(10)}
    assert len(tests) > 1


# -------------------------------------------------------------- detectors
@pytest.mark.skipif(not HAVE_V3, reason="dataset_v3 not present")
def test_paper_detector_matches_phase1():
    """Phase 2 engine must reproduce the Phase 1 primary-split result exactly."""
    d = core.load_v3()
    tr, te = core.primary_split(d)
    m, _ = core.run_det(core.DETECTORS["paper: fused XGB+SGD (aug)"], core.sub(d, tr), core.sub(d, te))
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (46, 2, 18, 61)


@pytest.mark.skipif(not HAVE_V3, reason="dataset_v3 not present")
def test_unsupervised_detectors_never_see_attacks(monkeypatch):
    """The autoencoder and isolation forest must be fitted on benign training rows only."""
    d = core.load_v3()
    tr, te = core.primary_split(d)
    fitted = []

    class SpyMLP(core.MLPRegressor):
        def fit(self, X, Y):
            fitted.append(len(X)); return super().fit(X, Y)

    class SpyIF(core.IsolationForest):
        def fit(self, X, y=None, sample_weight=None):
            fitted.append(len(X)); return super().fit(X)

    monkeypatch.setattr(core, "MLPRegressor", SpyMLP)
    monkeypatch.setattr(core, "IsolationForest", SpyIF)
    core.run_det(core.DETECTORS["Autoencoder (benign-only)"], core.sub(d, tr), core.sub(d, te))
    core.run_det(core.DETECTORS["Isolation forest (benign-only)"], core.sub(d, tr), core.sub(d, te))
    n_benign_train = int((d.y[tr] == 0).sum())
    assert (d.y[tr] == 1).any()
    assert fitted == [n_benign_train, n_benign_train]


def test_feature_subset_columns():
    assert core.cols(["pkt_count", "energy_j"]) == [FEATURE_ORDER_V2.index("pkt_count"), FEATURE_ORDER_V2.index("energy_j")]


# -------------------------------------------------------------- validator
def _rec(label, aclass, rid, t, **over):
    f = {k: 0.1 for k in FEATURE_ORDER_V2}
    f.update(over)
    return {"schema_version": "2.0.0", "features": f, "label": label, "attack_class": aclass,
            "run_id": rid, "window_start_epoch": t, "window_end_epoch": t + 5}


def test_validator_flags_missing_attack_class_and_dead_monitor(tmp_path):
    p = tmp_path / "d.jsonl"
    recs = [_rec("malware", "", "r1", 0), _rec("benign", "", "b1", 5)]
    p.write_text("\n".join(json.dumps(r) for r in recs))
    fails, warns, info = validate(str(p))
    assert any("without attack_class" in f for f in fails)
    assert any("syscall monitor looks dead" in f for f in fails)


def test_validator_episode_warning(tmp_path):
    p = tmp_path / "d.jsonl"
    recs = [_rec("malware", "scan", "r1", i * 5, sys_count=i / 10, energy_cpu_util=i / 10) for i in range(4)]
    p.write_text("\n".join(json.dumps(r) for r in recs))
    fails, warns, _ = validate(str(p), min_episodes=3)
    assert not fails
    assert any("scan has 1 episode" in w for w in warns)


# ---------------------------------------------------------- Oct 3 rebuild
@pytest.mark.skipif(not os.path.exists(core.DATA_OCT3), reason="Oct 3 reconstruction not built")
def test_oct3_reconstruction_is_scaled_and_labelled():
    recs = [json.loads(l) for l in open(core.DATA_OCT3)]
    vals = [v for r in recs for v in r["features"].values()]
    assert min(vals) >= 0.0 and max(vals) <= 1.0          # Phase 1 bug: raw values up to 897
    mal = [r for r in recs if r["label"] == "malware"]
    assert mal and all(r["attack_class"] == "scan" for r in mal)
    assert all(r["attack_class_source"] == "inferred_from_manifest_command" for r in mal)


def test_collection_scripts_parse():
    for s in ("collect_session.sh", "run_protocol.sh", "build_dataset.sh"):
        subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", s)], check=True)
