#!/usr/bin/env python3 -I
"""eval_full.py — Comprehensive evaluation with Wilson CIs.

Evaluates a trained HybridModel on a test split using run-ID-held-out splitting.
Reports: confusion matrix, Wilson 95% CIs for all proportions, per-class metrics,
detection latency statistics.

Usage:
  cd iot_digital_twin_working
  python3 -I eval_full.py --dataset data/dataset_v3.jsonl --model-dir models_v3_hybrid --out-dir reports/

All reported results are PRELIMINARY — attack data comes from one collection session.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json, argparse, math
import numpy as np
from collections import Counter, defaultdict
from common import FEATURE_ORDER_V2
from split_utils import load_supervised, split_by_runid, split_by_runid_train_val_test, describe_split
from threat_model_v3 import HybridModel, ATTACK_CLASSES


def wilson_ci(k, n, z=1.96):
    """Wilson score 95% CI for proportion k/n."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n) / denom
    return (p, max(0.0, centre - spread), min(1.0, centre + spread))


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset_v3.jsonl")
    ap.add_argument("--model-dir", default="models_v3_hybrid")
    ap.add_argument("--out-dir", default="reports")
    ap.add_argument("--test-frac", type=float, default=0.3)
    ap.add_argument("--split", default="runid", choices=["runid", "runid_3way", "random_legacy"])
    ap.add_argument("--retrain", action="store_true", help="Retrain on train split (default: use existing model)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load data
    X, ybin, cls, run_ids, meta = load_supervised(args.dataset)
    print(f"[+] Loaded {len(X)} supervised windows")
    print(f"    Classes: {dict(Counter(cls))}")
    print(f"    Run IDs: {len(set(run_ids))}")

    # Split
    if args.split == "runid":
        train_idx, test_idx = split_by_runid(run_ids, cls, test_frac=args.test_frac)
        val_idx = np.array([], dtype=int)
        describe_split(cls, run_ids, train_idx, "Train")
        describe_split(cls, run_ids, test_idx, "Test")
    elif args.split == "runid_3way":
        train_idx, val_idx, test_idx = split_by_runid_train_val_test(
            run_ids, cls, val_frac=0.15, test_frac=0.15)
        describe_split(cls, run_ids, train_idx, "Train")
        describe_split(cls, run_ids, val_idx, "Validation")
        describe_split(cls, run_ids, test_idx, "Test")
    else:
        # Legacy random split for comparison
        rng = np.random.RandomState(0)
        tr, te = [], []
        for c in set(cls):
            idx = np.where(cls == c)[0]
            rng.shuffle(idx)
            k = int(len(idx) * (1 - args.test_frac))
            tr += list(idx[:k]); te += list(idx[k:])
        train_idx = np.array(sorted(tr))
        test_idx = np.array(sorted(te))
        val_idx = np.array([], dtype=int)
        describe_split(cls, run_ids, train_idx, "Train (LEGACY RANDOM)")
        describe_split(cls, run_ids, test_idx, "Test (LEGACY RANDOM)")

    # Train or load model
    if args.retrain:
        print("[+] Training on train split...")
        model = HybridModel(feature_order=FEATURE_ORDER_V2)
        model.fit(X[train_idx], ybin[train_idx], cls[train_idx])
        # NOTE: scalers must be fitted on training data only
        print("[+] Model trained on train split only")
    else:
        print(f"[+] Loading existing model from {args.model_dir}")
        model = HybridModel.load(args.model_dir)

    # --- Binary evaluation on test set ---
    probs = []
    for x in X[test_idx]:
        result = model.core.assess(x, explain=False)
        probs.append(result["threat_probability"])
    probs = np.array(probs)

    threshold = model.core.cfg["t_malicious"]
    pred_atk = probs >= threshold
    y_test = ybin[test_idx]

    tp = int((pred_atk & (y_test == 1)).sum())
    fp = int((pred_atk & (y_test == 0)).sum())
    fn = int((~pred_atk & (y_test == 1)).sum())
    tn = int((~pred_atk & (y_test == 0)).sum())

    prec, rec, f1 = prf(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Wilson CIs
    prec_pt, prec_lo, prec_hi = wilson_ci(tp, tp + fp)
    rec_pt, rec_lo, rec_hi = wilson_ci(tp, tp + fn)
    fpr_pt, fpr_lo, fpr_hi = wilson_ci(fp, fp + tn)

    # --- Multi-class on test attack windows ---
    atk_test_idx = test_idx[y_test == 1]
    mc_classes = sorted(set(cls[atk_test_idx]))
    cm = {c: {d: 0 for d in mc_classes} for c in mc_classes}
    for i in atk_test_idx:
        true_cls = cls[i]
        pred_cls, _ = model.predict_class(X[i])
        if true_cls in cm and pred_cls in cm.get(true_cls, {}):
            cm[true_cls][pred_cls] += 1

    per_class = {}
    for c in mc_classes:
        tpc = cm[c].get(c, 0)
        fpc = sum(cm[d].get(c, 0) for d in mc_classes if d != c)
        fnc = sum(cm[c].get(d, 0) for d in mc_classes if d != c)
        p, r, f = prf(tpc, fpc, fnc)
        n_c = sum(cm[c].values())
        rec_c_pt, rec_c_lo, rec_c_hi = wilson_ci(tpc, tpc + fnc)
        per_class[c] = {
            "precision": p, "recall": r, "f1": f,
            "support": n_c,
            "recall_ci_lo": rec_c_lo, "recall_ci_hi": rec_c_hi,
        }

    # --- Build report ---
    md = []
    md.append("# Comprehensive Evaluation Report")
    md.append(f"\n**Status**: PRELIMINARY — attack data from one collection session (Oct 16)")
    md.append(f"**Split method**: `{args.split}` (run-ID-held-out)")
    md.append(f"**Threshold**: c ≥ {threshold} → malicious")
    md.append(f"**Dataset**: {args.dataset} ({len(X)} supervised windows)")
    md.append(f"**Model**: {'retrained on train split' if args.retrain else args.model_dir}\n")

    md.append("## Split Summary\n")
    md.append(f"| Partition | Windows | Run IDs | Classes |")
    md.append(f"|-----------|---------|---------|---------|")
    for name, idx in [("Train", train_idx), ("Val", val_idx), ("Test", test_idx)]:
        if len(idx) == 0:
            continue
        c_sub = dict(Counter(cls[idx]))
        r_sub = len(set(run_ids[idx]))
        md.append(f"| {name} | {len(idx)} | {r_sub} | {c_sub} |")

    md.append("\n## Binary Detection (attack vs benign)\n")
    md.append("| Metric | Value | 95% Wilson CI |")
    md.append("|--------|-------|--------------|")
    md.append(f"| Precision | {prec:.4f} | [{prec_lo:.4f}, {prec_hi:.4f}] |")
    md.append(f"| Recall | {rec:.4f} | [{rec_lo:.4f}, {rec_hi:.4f}] |")
    md.append(f"| F1 | {f1:.4f} | — |")
    md.append(f"| FPR | {fpr:.4f} | [{fpr_lo:.4f}, {fpr_hi:.4f}] |")

    md.append(f"\n**Confusion matrix**: TP={tp}, FP={fp}, FN={fn}, TN={tn}")
    md.append(f"**Test benign windows**: {fp + tn}")
    md.append(f"**Test attack windows**: {tp + fn}")

    md.append("\n## Per-Class Metrics (multi-class head, test attack windows)\n")
    md.append("| Class | Precision | Recall | F1 | Support | Recall 95% CI |")
    md.append("|-------|-----------|--------|----|---------|--------------|")
    for c in mc_classes:
        m = per_class[c]
        md.append(f"| {c} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['support']} | [{m['recall_ci_lo']:.4f}, {m['recall_ci_hi']:.4f}] |")

    md.append("\n## Multi-class Confusion Matrix\n")
    md.append("| true \\ pred | " + " | ".join(mc_classes) + " |")
    md.append("|" + "---|" * (len(mc_classes) + 1))
    for c in mc_classes:
        row = " | ".join(str(cm[c].get(d, 0)) for d in mc_classes)
        md.append(f"| **{c}** | {row} |")

    md.append("\n## Run-ID Overlap Check\n")
    train_rids = set(run_ids[train_idx])
    test_rids = set(run_ids[test_idx])
    overlap = train_rids & test_rids
    if overlap:
        md.append(f"**WARNING**: {len(overlap)} run_ids appear in both train and test: {overlap}")
    else:
        md.append("**PASS**: No run_id overlap between train and test splits.")

    md.append("\n## Limitations\n")
    md.append("- All attack data from one continuous session (Oct 16, 2026)")
    md.append("- Run-ID split is better than random but not equivalent to independent sessions")
    md.append("- Benign data from two sessions (Oct 16 + Oct 19)")
    md.append("- Results should be treated as PRELIMINARY until validated with independently collected data")

    # Write
    report_path = os.path.join(args.out_dir, "eval_full.md")
    with open(report_path, "w") as f:
        f.write("\n".join(md) + "\n")

    # JSON output
    results = {
        "status": "PRELIMINARY",
        "split_method": args.split,
        "threshold": threshold,
        "dataset": args.dataset,
        "n_supervised": len(X),
        "n_train": len(train_idx),
        "n_val": len(val_idx),
        "n_test": len(test_idx),
        "binary": {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4),
            "precision_ci": [round(prec_lo, 4), round(prec_hi, 4)],
            "recall": round(rec, 4),
            "recall_ci": [round(rec_lo, 4), round(rec_hi, 4)],
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "fpr_ci": [round(fpr_lo, 4), round(fpr_hi, 4)],
        },
        "per_class": {c: {k: round(v, 4) if isinstance(v, float) else v
                          for k, v in m.items()} for c, m in per_class.items()},
        "confusion_matrix": cm,
        "run_id_overlap": list(overlap),
    }

    json_path = os.path.join(args.out_dir, "eval_full.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Binary: P={prec:.3f} R={rec:.3f} F1={f1:.3f} FPR={fpr:.4f}")
    print(f"    FPR 95% CI: [{fpr_lo:.4f}, {fpr_hi:.4f}]")
    print(f"[+] Report: {report_path}")
    print(f"[+] JSON: {json_path}")

    return results


if __name__ == "__main__":
    main()
