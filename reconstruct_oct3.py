#!/usr/bin/env python3 -I
"""reconstruct_oct3.py — Assess and reconstruct Oct 3 raw data into dataset_v3 format.

Reads schema-v1 raw session files, checks feature compatibility with
FEATURE_ORDER_V2, and writes reconstructed records as UNLABELLED.

Does NOT assign labels. The data remains unlabelled until collection
conditions are verified by the original collector.

Usage:
  cd iot_digital_twin_working
  python3 -I reconstruct_oct3.py --raw-dir data/raw/ --out data/dataset_oct3_reconstructed.jsonl --report reports/oct3_reconstruction.md
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json, argparse, glob
from collections import Counter
from common import FEATURE_ORDER_V2

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default="data/raw/")
    ap.add_argument("--out", default="data/dataset_oct3_reconstructed.jsonl")
    ap.add_argument("--report", default="reports/oct3_reconstruction.md")
    args = ap.parse_args()

    raw_files = sorted(glob.glob(os.path.join(args.raw_dir, "session_20261003*.jsonl")))
    if not raw_files:
        print("No Oct 3 raw files found in", args.raw_dir)
        return

    print(f"Found {len(raw_files)} Oct 3 raw files")

    total_windows = 0
    reconstructed = 0
    missing_features = Counter()
    extra_features = Counter()
    file_summaries = []

    all_records = []

    for fpath in raw_files:
        fname = os.path.basename(fpath)
        windows = []
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    windows.append(rec)
                except json.JSONDecodeError:
                    continue

        n_windows = len(windows)
        total_windows += n_windows

        # Check feature compatibility
        n_compatible = 0
        for w in windows:
            raw = w.get("raw", {})
            if not isinstance(raw, dict):
                continue
            present = set(raw.keys())
            needed = set(FEATURE_ORDER_V2)
            missing = needed - present
            extra = present - needed
            for m in missing:
                missing_features[m] += 1
            for e in extra:
                extra_features[e] += 1

            if not missing:
                n_compatible += 1
                # Reconstruct
                features = {k: float(raw[k]) for k in FEATURE_ORDER_V2}
                out_rec = {
                    "schema_version": "2.0.0",
                    "device_ip": "192.168.0.1",
                    "firmware_id": "DIR-868L_revB_2-05b02",
                    "mirror_if": "twin-mon",
                    "window_start_epoch": w.get("window_start_epoch"),
                    "window_end_epoch": w.get("window_end_epoch"),
                    "features": features,
                    "label": "unlabeled",
                    "attack_class": "",
                    "run_id": fname.replace(".jsonl", ""),
                    "source": "oct3_reconstruction",
                    "original_file": fname,
                }
                all_records.append(out_rec)
                reconstructed += 1

        file_summaries.append({
            "file": fname,
            "windows": n_windows,
            "compatible": n_compatible,
        })
        print(f"  {fname}: {n_windows} windows, {n_compatible} compatible")

    # Write reconstructed (but unlabelled)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    # Write report
    md = []
    md.append("# Oct 3 Raw Data Reconstruction Assessment")
    md.append(f"\n**Total raw files**: {len(raw_files)}")
    md.append(f"**Total windows**: {total_windows}")
    md.append(f"**Successfully reconstructed**: {reconstructed}")
    md.append(f"**Output**: `{args.out}`")
    md.append(f"\n**IMPORTANT**: All reconstructed records are labelled `unlabeled`.")
    md.append("Do NOT relabel as benign without confirmation from the original collector.\n")

    md.append("## Per-file Summary\n")
    md.append("| File | Windows | Compatible |")
    md.append("|------|---------|-----------|")
    for fs in file_summaries:
        md.append(f"| `{fs['file']}` | {fs['windows']} | {fs['compatible']} |")

    if missing_features:
        md.append("\n## Missing Features (across all incompatible windows)\n")
        md.append("| Feature | Windows missing it |")
        md.append("|---------|-------------------|")
        for feat, cnt in missing_features.most_common():
            md.append(f"| `{feat}` | {cnt} |")

    md.append("\n## Feature Compatibility\n")
    if reconstructed == total_windows:
        md.append("**All Oct 3 windows contain all 45 FEATURE_ORDER_V2 features.** Reconstruction is fully compatible.")
    else:
        md.append(f"**{reconstructed}/{total_windows} windows** are fully compatible with FEATURE_ORDER_V2.")

    md.append("\n## Next Steps\n")
    md.append("1. Confirm with original collector whether Oct 3 sessions were benign-only")
    md.append("2. If confirmed benign, relabel with `label_session.py`")
    md.append("3. Use as additional benign data for FPR estimation (from an independent date)")

    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w") as f:
        f.write("\n".join(md) + "\n")

    print(f"\nReport: {args.report}")
    print(f"Reconstructed JSONL: {args.out} ({reconstructed} records, all UNLABELLED)")

if __name__ == "__main__":
    main()
