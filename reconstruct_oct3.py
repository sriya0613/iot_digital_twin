#!/usr/bin/env python3 -I
"""reconstruct_oct3.py — rebuild the Oct 3 raw sessions on the SAME scale as dataset_v3.

v2 of this script (Phase 2). The Phase 1 version copied RAW (unscaled) values into the
features dict, so its output was not comparable with dataset_v3 even though it was
reported as "fully compatible". That was wrong; this version fixes it.

What it does, using the project's own pipeline code (stream/pipeline.py):
  1. scales each raw window with the FROZEN v3 scaler (data/scaler_v3.json) via apply_scaler,
     so values are on exactly the scale the v3 model was trained on (out-of-range -> clipped);
  2. labels each window with Labeler(data/run_manifest.jsonl) - the same rule run.py build uses.
     The Oct 3 manifest has 1 benign run, 9 malware runs and 3 healing runs.
  3. The Oct 3 manifest predates --attack-class. All 9 malware runs record the command
     `sudo nmap -T4 -p 1-1000 192.168.0.1`, so attack_class is set to "scan" and the record
     carries attack_class_source = "inferred_from_manifest_command" so this is never hidden.

Usage:
  python3 -I reconstruct_oct3.py
"""
import argparse
import glob
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "stream"))
from common import FEATURE_ORDER_V2  # noqa: E402
from pipeline import Labeler, apply_scaler, load_scaler  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-glob", default=os.path.join(HERE, "data/raw/session_20261003*.jsonl"))
    ap.add_argument("--scaler", default=os.path.join(HERE, "data/scaler_v3.json"))
    ap.add_argument("--manifest", default=os.path.join(HERE, "data/run_manifest.jsonl"))
    ap.add_argument("--out", default=os.path.join(HERE, "data/dataset_oct3_reconstructed.jsonl"))
    ap.add_argument("--report", default=os.path.join(HERE, "reports/oct3_reconstruction.md"))
    a = ap.parse_args()

    scaler = load_scaler(a.scaler)
    labeler = Labeler(a.manifest)
    manifest = [json.loads(l) for l in open(a.manifest) if l.strip()]
    notes = {m["run_id"]: m.get("note", "") for m in manifest}

    out, per_file, clipped = [], [], Counter()
    for path in sorted(glob.glob(a.raw_glob)):
        n = 0
        for line in open(path):
            if not line.strip():
                continue
            w = json.loads(line)
            raw = w.get("raw", {})
            s, e = float(w["window_start_epoch"]), float(w["window_end_epoch"])
            for k in FEATURE_ORDER_V2:
                lo, hi = scaler.get(k, [0.0, 0.0])
                if hi > lo and (raw.get(k, 0.0) < lo or raw.get(k, 0.0) > hi):
                    clipped[k] += 1
            feats = apply_scaler(raw, scaler)
            label, run_id, aclass = labeler.label(s, e)
            src = "manifest"
            if label == "malware" and not aclass:
                if "nmap" in notes.get(run_id, ""):
                    aclass, src = "scan", "inferred_from_manifest_command"
                else:
                    src = "missing"
            out.append({"schema_version": "2.0.0", "device_ip": "192.168.0.1",
                        "firmware_id": "DIR-868L_revB_2-05b02",
                        "window_start_epoch": s, "window_end_epoch": e,
                        "features": {k: float(feats[k]) for k in FEATURE_ORDER_V2},
                        "label": label or "unlabeled", "attack_class": aclass or "",
                        "attack_class_source": src if label == "malware" else "",
                        "run_id": run_id, "source": "oct3_reconstruction_v2",
                        "original_file": os.path.basename(path)})
            n += 1
        per_file.append((os.path.basename(path), n))

    with open(a.out, "w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")

    lab = Counter((r["label"], r["attack_class"]) for r in out)
    runs = Counter((r["label"], r["attack_class"], r["run_id"]) for r in out if r["run_id"])
    sup = [r for r in out if r["label"] in ("benign", "malware")]
    const = [k for k in FEATURE_ORDER_V2 if len({r["features"][k] for r in sup}) <= 1]

    md = ["# Oct 3 Raw Data Reconstruction (v2 — corrected)", "",
          "**Correction to Phase 1:** the Phase 1 version of this script wrote raw, unscaled values "
          "(e.g. `pkt_count` up to 897) while dataset_v3 is min-max scaled to [0,1]. Its claim of "
          "\"fully compatible\" was wrong. Phase 1 also said the Oct 3 sessions had no labels; "
          "in fact `data/run_manifest.jsonl` labels them. This version rescales with the frozen "
          "`scaler_v3.json` and labels from the manifest using `stream/pipeline.py`.", "",
          "**Windows**: %d from %d raw files" % (len(out), len(per_file)), "",
          "| File | Windows |", "|---|---|"]
    md += ["| `%s` | %d |" % p for p in per_file]
    md += ["", "## Labels (from manifest)", "", "| label | attack_class | windows |", "|---|---|---|"]
    md += ["| %s | %s | %d |" % (l, c or "-", n) for (l, c), n in sorted(lab.items())]
    md += ["", "**Labelled runs**: " + ", ".join("%s/%s:%d" % (l, c or "-", n) for (l, c, _), n in sorted(runs.items())), "",
           "**attack_class provenance**: the Oct 3 manifest has no `attack_class` field. Every Oct 3 malware "
           "run's recorded command is `sudo nmap -T4 -p 1-1000 192.168.0.1`, so these windows are marked "
           "`scan` with `attack_class_source = inferred_from_manifest_command`.", "",
           "## Scale check", "",
           "Raw values outside the v3 scaler's range were clipped to [0,1] (count of windows per feature):", ""]
    md += ["- `%s`: %d" % kv for kv in clipped.most_common()] or ["- none"]
    md += ["", "Features constant across Oct 3 supervised windows (%d): %s" % (len(const), ", ".join("`%s`" % k for k in const)), "",
           "## Use", "",
           "Oct 3 is a separate day, twin boot and recorder run from the Oct 16 training data, so its "
           "benign and scan windows serve as a **cross-session test** (Phase 2, EXP-6). It contains one "
           "attack class (scan, lower-volume `-p 1-1000` than Oct 16's `-p 1-65535`) and one benign run."]
    os.makedirs(os.path.dirname(a.report), exist_ok=True)
    with open(a.report, "w") as f:
        f.write("\n".join(md) + "\n")
    print("wrote %d windows; labels %s" % (len(out), dict(lab)))
    print("clipped:", dict(clipped.most_common(8)))


if __name__ == "__main__":
    main()
