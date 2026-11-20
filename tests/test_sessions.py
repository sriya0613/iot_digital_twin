#!/usr/bin/env python3 -I
"""test_sessions.py — session IDs (merge_sessions.py) and the session-held-out split (split_utils.py).

  python3 -I -m pytest tests/test_sessions.py -v
"""
import json
import os
import subprocess
import sys

import numpy as np
import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import merge_sessions as ms  # noqa: E402
from split_utils import load_session_split, split_by_session, session_ids_of  # noqa: E402

DAY = 86400
T0 = 1792000000.0          # 2026-10-14 UTC (legacy era)
T1 = T0 + 30 * DAY         # new sessions start here


def win(t, label="benign", run="r"):
    return {"window_start_epoch": t, "window_end_epoch": t + 5, "label": label, "run_id": run}


def sess(sid, start, stop):
    return {"session_id": sid, "start_epoch": start, "stop_epoch": stop}


# ------------------------------------------------------------------ assignment
def test_assign_sessions_legacy_and_gaps():
    s = [sess("S01", T1, T1 + 1000), sess("S02", T1 + 2000, T1 + 3000)]
    w = [win(T0), win(T1 + 10), win(T1 + 1500), win(T1 + 2990), win(T1 + 5000)]
    got = ms.assign(w, s)
    assert got[0] == "L20261014"
    assert got[1:] == ["S01", None, "S02", None]


def test_window_just_before_first_session_is_not_legacy():
    """Pilot S00: the recorder started 9 s before the session; that window must not become 'L<date>'."""
    s = [sess("S00", T1, T1 + 1000)]
    assert ms.assign([win(T1 - 9)], s) == [None]
    assert T1 > ms.LEGACY_BEFORE > T0


def test_window_assigned_by_midpoint():
    s = [sess("S01", T1, T1 + 100)]
    assert ms.assign([win(T1 - 2)], s) == ["S01"]       # midpoint T1+0.5 inside
    assert ms.assign([win(T1 + 98)], s) == [None]       # midpoint T1+100.5 outside


def test_overlap_and_open_session_rejected(tmp_path):
    d = tmp_path / "s"; d.mkdir()
    (d / "S01.json").write_text(json.dumps(sess("S01", 0, 100)))
    (d / "S02.json").write_text(json.dumps(sess("S02", 50, 150)))
    with pytest.raises(ValueError, match="overlap"):
        ms.load_sessions(str(d))
    (d / "S02.json").write_text(json.dumps(sess("S02", 200, None)))
    with pytest.raises(ValueError, match="no stop_epoch"):
        ms.load_sessions(str(d))
    assert ms.load_sessions(str(d), allow_open=True)[1]["stop_epoch"] == float("inf")


def test_pilot_session_files_are_loaded(tmp_path):
    d = tmp_path / "s"; d.mkdir()
    (d / "P01.json").write_text(json.dumps(sess("P01", T1, T1 + 100)))
    assert ms.assign([win(T1 + 10)], ms.load_sessions(str(d))) == ["P01"]


def test_cli_writes_new_file_and_flags_orphans(tmp_path):
    d = tmp_path / "s"; d.mkdir()
    (d / "S01.json").write_text(json.dumps(sess("S01", T1, T1 + 100)))
    data = tmp_path / "ds.jsonl"
    rows = [win(T1 + 10), win(T1 + 500, "malware", "orphan-run")]
    data.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    before = data.read_bytes()
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "merge_sessions.py"), str(data),
                        "--sessions-dir", str(d)], capture_output=True, text=True)
    assert r.returncode == 1 and "orphan-run" in r.stdout          # labelled window outside sessions
    assert data.read_bytes() == before                              # input untouched
    out = [json.loads(l) for l in open(tmp_path / "ds_sessions.jsonl")]
    assert [o["session_id"] for o in out] == ["S01", None]


# ------------------------------------------------------------------ split
def write_split(tmp_path, spec):
    p = tmp_path / "split.json"
    p.write_text(json.dumps(spec))
    return str(p)


def test_split_valid_and_indices(tmp_path):
    split = load_session_split(write_split(tmp_path, {"train": ["L20261016", "S01"], "val": ["S02"], "test": ["S03"]}))
    ids = np.array(["S01", "S02", "S03", "L20261016", None, "S99", "S03"], dtype=object)
    tr, va, te, un = split_by_session(ids, split)
    assert tr.tolist() == [0, 3] and va.tolist() == [1] and te.tolist() == [2, 6] and un.tolist() == [4, 5]


@pytest.mark.parametrize("spec,msg", [
    ({"train": ["S01"], "val": ["S01"], "test": ["S02"]}, "both"),
    ({"train": ["S01"], "val": ["L20261016"], "test": ["S02"]}, "legacy"),
    ({"train": ["S01"], "val": [], "test": ["S02"]}, "non-empty"),
    ({"train": ["S01", "P01"], "val": ["S03"], "test": ["S02"]}, "pilot"),
    ({"train": ["S01"], "test": ["S02"]}, "non-empty"),
])
def test_split_rejects_bad_files(tmp_path, spec, msg):
    with pytest.raises(ValueError, match=msg):
        load_session_split(write_split(tmp_path, spec))


def test_template_is_a_valid_split():
    split = load_session_split(os.path.join(ROOT, "data", "session_split.template.json"))
    parts = {p: sorted(s for s, q in split.items() if q == p) for p in ("train", "val", "test")}
    assert len(parts["val"]) == 3 and len(parts["test"]) == 3
    assert all(not s.startswith("L") for s in parts["val"] + parts["test"])


def test_registered_split_is_valid_and_unchanged_in_shape():
    p = os.path.join(ROOT, "data", "session_split.json")
    if not os.path.exists(p):
        pytest.skip("split not registered yet")
    spec = json.load(open(p))
    assert spec["registered"]                                   # a date, set before S01
    split = load_session_split(p)
    assert sorted(s for s, q in split.items() if q == "test") == ["S07", "S12", "S16"]
    assert not set(spec.get("spares", [])) & set(split)         # spares are not in any part until substituted


def test_session_ids_of_meta():
    assert session_ids_of([{"session_id": "S01"}, {}]).tolist() == ["S01", None]
