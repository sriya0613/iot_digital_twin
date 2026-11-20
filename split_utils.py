#!/usr/bin/env python3 -I
"""split_utils.py — Leakage-resistant data splitting utilities.

Provides:
  split_by_runid()   — groups by run_id, keeps entire runs together
  split_by_session() — groups by session, keeps entire sessions together

Both enforce: no random distribution of adjacent 5-second windows across splits.
All scalers/preprocessing must be fitted on training data only.

Usage:
  from split_utils import split_by_runid, load_supervised
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import numpy as np
from collections import defaultdict
from common import FEATURE_ORDER_V2


def load_supervised(path, feature_order=None):
    """Load dataset, returning only supervised (benign + malware) windows.

    Returns: X (n, d), ybin (n,), cls (n,), run_ids (n,), meta list
    """
    if feature_order is None:
        feature_order = FEATURE_ORDER_V2

    X, ybin, cls, run_ids, meta = [], [], [], [], []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            label = r.get("label", "")
            if label not in ("benign", "malware"):
                continue
            f = r["features"]
            X.append([float(f[k]) for k in feature_order])
            c = r.get("attack_class", "") or ""
            is_atk = (label == "malware") or (c != "")
            ybin.append(1 if is_atk else 0)
            cls.append(c if is_atk else "benign")
            run_ids.append(str(r.get("run_id", "NONE")))
            meta.append(r)

    return (np.array(X, float), np.array(ybin, int),
            np.array(cls, dtype=object), np.array(run_ids, dtype=object), meta)


def split_by_runid(run_ids, cls, test_frac=0.3, seed=0):
    """Split by run_id: entire run_ids go to train or test.

    Within each class, sort run_ids lexicographically (approximates chronological
    order since run_ids embed timestamps), then assign last `test_frac` of run_ids
    to test.

    Returns: train_indices, test_indices (sorted numpy arrays)
    """
    rng = np.random.RandomState(seed)
    train_idx, test_idx = [], []

    # Group indices by class
    class_runs = defaultdict(lambda: defaultdict(list))
    for i, (rid, c) in enumerate(zip(run_ids, cls)):
        class_runs[c][rid].append(i)

    for c in sorted(class_runs.keys()):
        runs = class_runs[c]
        # Sort run_ids (lexicographic ≈ chronological for timestamp-based IDs)
        sorted_rids = sorted(runs.keys())
        n_runs = len(sorted_rids)
        n_test_runs = max(1, int(n_runs * test_frac))
        n_train_runs = n_runs - n_test_runs

        train_rids = sorted_rids[:n_train_runs]
        test_rids = sorted_rids[n_train_runs:]

        for rid in train_rids:
            train_idx.extend(runs[rid])
        for rid in test_rids:
            test_idx.extend(runs[rid])

    return np.array(sorted(train_idx)), np.array(sorted(test_idx))


def split_by_runid_train_val_test(run_ids, cls, val_frac=0.15, test_frac=0.15, seed=0):
    """Three-way split by run_id: train / validation / test.

    - Training: model fitting and feature preprocessing (scalers fitted here only)
    - Validation: hyperparameter selection, threshold calibration, model selection
    - Final test: one-time evaluation of frozen pipeline

    Returns: train_indices, val_indices, test_indices
    """
    train_idx, val_idx, test_idx = [], [], []

    class_runs = defaultdict(lambda: defaultdict(list))
    for i, (rid, c) in enumerate(zip(run_ids, cls)):
        class_runs[c][rid].append(i)

    for c in sorted(class_runs.keys()):
        runs = class_runs[c]
        sorted_rids = sorted(runs.keys())
        n_runs = len(sorted_rids)

        n_test = max(1, int(n_runs * test_frac))
        n_val = max(1, int(n_runs * val_frac))
        n_train = n_runs - n_val - n_test

        if n_train < 1:
            # Too few run_ids: put all but last in train, last in test, skip val
            n_train = max(1, n_runs - 1)
            n_test = n_runs - n_train
            n_val = 0

        train_rids = sorted_rids[:n_train]
        val_rids = sorted_rids[n_train:n_train + n_val]
        test_rids = sorted_rids[n_train + n_val:]

        for rid in train_rids:
            train_idx.extend(runs[rid])
        for rid in val_rids:
            val_idx.extend(runs[rid])
        for rid in test_rids:
            test_idx.extend(runs[rid])

    return (np.array(sorted(train_idx)),
            np.array(sorted(val_idx)),
            np.array(sorted(test_idx)))


# ----------------------------------------------------------------- session-held-out split
SPLIT_PARTS = ("train", "val", "test")


def load_session_split(path):
    """Read and check a pre-registered split file:
        {"train": ["S01", ..., "L20261016"], "val": [...], "test": [...], "registered": "<date>"}
    Checks: all three parts present, no session in two parts, legacy sessions (L*) only in train,
    at least one session in each part. Returns {session_id: part}."""
    with open(path) as f:
        spec = json.load(f)
    where = {}
    for part in SPLIT_PARTS:
        ids = spec.get(part)
        if not isinstance(ids, list) or not ids:
            raise ValueError("%s: '%s' must be a non-empty list" % (path, part))
        for sid in ids:
            if sid in where:
                raise ValueError("%s: session %s is in both %s and %s" % (path, sid, where[sid], part))
            if str(sid).startswith("P"):
                raise ValueError("%s: pilot session %s may not be used in any split" % (path, sid))
            if str(sid).startswith("L") and part != "train":
                raise ValueError("%s: legacy session %s may only be used for training" % (path, sid))
            where[sid] = part
    return where


def split_by_session(session_ids, split):
    """Indices for train / val / test from per-window session ids and a split from load_session_split().
    Windows whose session is not in the split (None, or not registered) are returned separately and
    never used. Returns (train_idx, val_idx, test_idx, unassigned_idx)."""
    parts = {p: [] for p in SPLIT_PARTS + ("unassigned",)}
    for i, sid in enumerate(session_ids):
        parts[split.get(sid, "unassigned")].append(i)
    return tuple(np.array(parts[p], dtype=int) for p in SPLIT_PARTS + ("unassigned",))


def session_ids_of(meta):
    """Per-window session ids from load_supervised()'s meta list (None if not merged)."""
    return np.array([m.get("session_id") for m in meta], dtype=object)


def describe_split(cls, run_ids, indices, name="split"):
    """Print a summary of a split partition."""
    c_sub = cls[indices]
    r_sub = run_ids[indices]
    from collections import Counter
    print(f"  {name}: {len(indices)} windows, "
          f"{len(set(r_sub))} run_ids, "
          f"classes: {dict(Counter(c_sub))}")
