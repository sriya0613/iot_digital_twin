"""experiments/core.py — shared data, splits, detectors and metrics for the Phase 2 experiments.

Every experiment uses the same three evaluation designs:
  primary    split_by_runid (deterministic, the Phase 1 split): whole runs go to train or test.
  repeated   N grouped random splits: per class, ~30% of run_ids (>=1) held out, seed 0..N-1.
             Gives a distribution instead of one number. With only 3-4 runs for beacon and
             bruteforce, every test set has just 1 episode of those classes - a hard data limit.
  oct3       train on all Oct 16/19 supervised windows, test on the Oct 3 session
             (different day, boot and recorder run; benign + low-volume scan only).
Scalers and models are fitted on the training part only, in every design.
"""
import math
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import threat_model as tm  # noqa: E402
from common import FEATURE_ORDER_V2, FEATURE_ORDER_V1, SYSCALL_FEATURES, ENERGY_FEATURES, effective_features  # noqa: E402
from split_utils import load_supervised, split_by_runid  # noqa: E402
from threat_model import ThreatModel, augment_scans  # noqa: E402
from threat_model_v3 import HybridModel, SEVERITY  # noqa: E402

from sklearn.ensemble import IsolationForest, RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score, average_precision_score  # noqa: E402
from sklearn.neural_network import MLPRegressor  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

DATA_V3 = os.path.join(ROOT, "data", "dataset_v3.jsonl")
DATA_OCT3 = os.path.join(ROOT, "data", "dataset_oct3_reconstructed.jsonl")
OUT_DIR = os.path.join(ROOT, "reports", "phase2")
ATTACKS = ["scan", "bruteforce", "dos", "beacon"]
FEATURE_SETS = {
    "network (28)": FEATURE_ORDER_V1,
    "network+syscall (39)": FEATURE_ORDER_V1 + SYSCALL_FEATURES,
    "network+energy (34)": FEATURE_ORDER_V1 + ENERGY_FEATURES,
    "syscall+energy (17)": SYSCALL_FEATURES + ENERGY_FEATURES,
    "all 3 monitors (45)": FEATURE_ORDER_V2,
    "effective non-constant (37)": effective_features(),
}


# ----------------------------------------------------------------- data
class Data:
    def __init__(self, X, y, c, r):
        self.X, self.y, self.c, self.r = X, y, c, r


def load_v3():
    X, y, c, r, _ = load_supervised(DATA_V3)
    return Data(X, y, c, r)


def load_oct3():
    X, y, c, r, _ = load_supervised(DATA_OCT3)
    return Data(X, y, c, r)


def cols(names):
    return [FEATURE_ORDER_V2.index(n) for n in names]


# --------------------------------------------------------------- splits
def primary_split(d):
    return split_by_runid(d.r, d.c, test_frac=0.3)


def grouped_split(d, seed, test_frac=0.3):
    rng = np.random.RandomState(seed)
    runs = defaultdict(lambda: defaultdict(list))
    for i, (rid, c) in enumerate(zip(d.r, d.c)):
        runs[c][rid].append(i)
    tr, te = [], []
    for c in sorted(runs):
        rids = sorted(runs[c])
        rng.shuffle(rids)
        k = max(1, int(round(len(rids) * test_frac)))
        k = min(k, len(rids) - 1)
        for rid in rids[:k]:
            te += runs[c][rid]
        for rid in rids[k:]:
            tr += runs[c][rid]
    return np.array(sorted(tr)), np.array(sorted(te))


# ------------------------------------------------------------ detectors
# Each factory returns fit(X, y, c, names) -> score(X) where score is "attack-ness" and
# a fixed decision threshold `thr`. Thresholds are fixed a priori, never tuned on test.
class Det:
    def __init__(self, name, fit, thr, kind):
        self.name, self.fit, self.thr, self.kind = name, fit, thr, kind


def _core(augment, part="fused", w_xgb=None):
    def fit(X, y, c, names):
        cfg = None if w_xgb is None else {"w_xgb": w_xgb, "w_inc": 1 - w_xgb}
        m = ThreatModel(cfg, names).fit(X, y, augment=augment)
        if part == "xgb":
            return m.p_xgb
        if part == "sgd":
            return m.p_inc
        return m.threat_probability
    return fit


def _sk(make, scale=False, augment=False):
    def fit(X, y, c, names):
        if augment:
            g = augment_scans(X[y == 1], names)
            if len(g):
                X = np.vstack([X, g]); y = np.r_[y, np.ones(len(g), int)]
        sc = StandardScaler().fit(X) if scale else None
        m = make().fit(sc.transform(X) if sc else X, y)
        return lambda Z: m.predict_proba(sc.transform(Z) if sc else Z)[:, 1]
    return fit


def _ae(X, y, c, names):
    """Same recipe as HybridModel: MLP autoencoder on benign train windows; score =
    reconstruction error / 99th percentile benign train error (>= 1 means anomalous)."""
    Xb = X[y == 0]
    h = max(2, X.shape[1] // 3)
    ae = MLPRegressor(hidden_layer_sizes=(h,), activation="relu", solver="adam", max_iter=600,
                      random_state=tm.SEED).fit(Xb, Xb)
    err = lambda Z: np.mean((Z - ae.predict(Z)) ** 2, axis=1)
    ref = float(np.percentile(err(Xb), 99)) or 1.0
    return lambda Z: err(Z) / ref


def _iforest(X, y, c, names):
    Xb = X[y == 0]
    m = IsolationForest(n_estimators=200, random_state=tm.SEED).fit(Xb)
    s = lambda Z: -m.score_samples(Z)
    ref = float(np.percentile(s(Xb), 99))
    return lambda Z: s(Z) / ref


def _one_rule(X, y, c, names):
    """Best single feature + threshold chosen on TRAIN by Youden's J (both directions)."""
    best = (-1, 0, 0.0, 1)
    for j in range(X.shape[1]):
        v = X[:, j]
        for t in np.unique(v):
            for sgn in (1, -1):
                p = (sgn * v >= sgn * t)
                tpr = (p & (y == 1)).sum() / max(1, (y == 1).sum())
                fpr = (p & (y == 0)).sum() / max(1, (y == 0).sum())
                if tpr - fpr > best[0]:
                    best = (tpr - fpr, j, t, sgn)
    _, j, t, sgn = best
    _one_rule.last = (names[j], float(t), sgn)
    return lambda Z: (sgn * Z[:, j] >= sgn * t).astype(float)


DETECTORS = {
    "paper: fused XGB+SGD (aug)": Det("paper", _core(True), 0.35, "supervised"),
    "fused XGB+SGD (no aug)": Det("fused_noaug", _core(False), 0.35, "supervised"),
    "XGBoost only (aug)": Det("xgb", _core(True, "xgb"), 0.5, "supervised"),
    "SGD only (aug)": Det("sgd", _core(True, "sgd"), 0.5, "supervised"),
    "Random forest": Det("rf", _sk(lambda: RandomForestClassifier(300, class_weight="balanced", random_state=tm.SEED, n_jobs=1)), 0.5, "supervised"),
    "Random forest (aug)": Det("rf_aug", _sk(lambda: RandomForestClassifier(300, class_weight="balanced", random_state=tm.SEED, n_jobs=1), augment=True), 0.5, "supervised"),
    "Logistic regression": Det("lr", _sk(lambda: LogisticRegression(max_iter=2000, class_weight="balanced"), scale=True), 0.5, "supervised"),
    "One-rule threshold": Det("onerule", _one_rule, 0.5, "supervised"),
    "Autoencoder (benign-only)": Det("ae", _ae, 1.0, "unsupervised"),
    "Isolation forest (benign-only)": Det("iforest", _iforest, 1.0, "unsupervised"),
}


# -------------------------------------------------------------- metrics
def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    sp = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (p, max(0.0, mid - sp), min(1.0, mid + sp))


def metrics(y, pred, score=None, runs=None, cls=None):
    y = np.asarray(y); pred = np.asarray(pred, bool)
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    P = wilson(tp, tp + fp); R = wilson(tp, tp + fn); F = wilson(fp, fp + tn)
    f1 = 2 * P[0] * R[0] / (P[0] + R[0]) if tp else 0.0
    m = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": P[0], "precision_ci": P[1:],
         "recall": R[0], "recall_ci": R[1:], "fpr": F[0], "fpr_ci": F[1:], "f1": f1}
    if score is not None and len(set(y)) == 2:
        s = np.nan_to_num(np.asarray(score, float))
        m["roc_auc"] = float(roc_auc_score(y, s)); m["pr_auc"] = float(average_precision_score(y, s))
    if runs is not None:
        # episode level: an attack run counts as detected if any of its windows is flagged
        ep = defaultdict(list)
        for yy, pp, rr in zip(y, pred, runs):
            if yy == 1:
                ep[rr].append(pp)
        det = sum(1 for v in ep.values() if any(v))
        m["episodes_detected"] = det; m["episodes"] = len(ep)
        m["first_detect_windows"] = [int(np.argmax(v)) if any(v) else None for v in ep.values()]
    if cls is not None:
        m["recall_by_class"] = {}
        for a in ATTACKS:
            k = np.asarray(cls) == a
            if k.any():
                m["recall_by_class"][a] = {"recall": float(pred[k].mean()), "n": int(k.sum())}
    return m


def run_det(det, d_tr, d_te, names=None):
    names = list(names or FEATURE_ORDER_V2)
    ix = cols(names)
    score = det.fit(d_tr.X[:, ix], d_tr.y, d_tr.c, names)
    s = score(d_te.X[:, ix])
    return metrics(d_te.y, s >= det.thr, s, d_te.r, d_te.c), s


def sub(d, idx):
    return Data(d.X[idx], d.y[idx], d.c[idx], d.r[idx])


def summarize(vals):
    v = np.array([x for x in vals if x is not None and not (isinstance(x, float) and math.isnan(x))], float)
    if not len(v):
        return {"mean": float("nan"), "std": float("nan"), "p2.5": float("nan"), "p97.5": float("nan"), "n": 0}
    return {"mean": float(v.mean()), "std": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
            "p2.5": float(np.percentile(v, 2.5)), "p97.5": float(np.percentile(v, 97.5)), "n": int(len(v))}


def fmt_ci(m, k):
    lo, hi = m[k + "_ci"]
    return "%.3f [%.3f, %.3f]" % (m[k], lo, hi)


def write(name, md, obj=None):
    import json
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, name + ".md"), "w") as f:
        f.write("\n".join(md) + "\n")
    if obj is not None:
        with open(os.path.join(OUT_DIR, name + ".json"), "w") as f:
            json.dump(obj, f, indent=2, default=lambda o: o.tolist() if hasattr(o, "tolist") else str(o))
