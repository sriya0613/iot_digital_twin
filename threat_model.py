"""threat_model.py — Module 4 (detection) + Module 5 (explanation).

    Fingerprint vector ─┬─> XGBoost ───────────┐
                        └─> Incremental model ─┴─> Probability fusion ─┬─> Threat probability
                                                                       └─> Threshold logic ─> Threat label

    Fingerprint + XGBoost model ─> SHAP explainer ─> Feature impact ─> Final risk score
"""
import json
import os

import numpy as np
import xgboost as xgb
from joblib import dump, load
from sklearn.linear_model import SGDClassifier

from common import FEATURE_ORDER_V1, WINDOW_SEC, schema_for

try:                                   # SHAP library if installed ...
    import shap
    HAVE_SHAP = True
except Exception:                      # ... otherwise XGBoost's built-in TreeSHAP (same values)
    HAVE_SHAP = False

DEFAULTS = {
    "w_xgb": 0.6, "w_inc": 0.4,        # probability fusion weights
    # Threshold logic. "malicious" sits just below w_inc so that EITHER model, when
    # fully confident on its own, is enough to raise the label (see evaluation.md).
    "t_suspicious": 0.15,              # >= -> "suspicious" (logged, no action)
    "t_malicious": 0.35,               # >= -> "malicious"  (triggers heal)
    "online_lo": 0.05, "online_hi": 0.95,   # only very confident windows update the incremental model
}
SEED = 0


# Features that grow with how big/fast a scan is, and features that grow with how
# many ports it touches. Used only by augment_scans().
_VOL_NAMES = ("pkt_count", "byte_count", "pkts_per_sec", "bytes_per_sec",
              "n_http", "n_https", "n_arp_req", "n_arp_reply", "n_broadcast")
_PORT_NAMES = ("n_unique_src_ports", "n_unique_dst_ports", "distinct_l4_services")
_AUG_VOLUMES = (0.003, 0.006, 0.012, 0.025, 0.05, 0.1, 0.2, 0.4)   # target pkt_count (normalised)
_AUG_PORTS = (1.0, 0.3, 0.1)


def augment_scans(X_attack, feature_order=FEATURE_ORDER_V1):
    """Volume-scaled copies of real attack windows.

    Every recorded scan in the first capture is large (2,000-42,000 packets per
    window), so a model trained on them alone learns "attack = huge volume" and
    misses a smaller scan of the same kind. For each real attack window this makes
    copies with the network volume features scaled down to smaller packet counts and
    the port-count features scaled to fewer ports. The protocol mix (TCP share, SYN
    and RST ratios) and any syscall/energy features are left exactly as recorded."""
    names = list(feature_order)
    X_attack = np.asarray(X_attack, float).reshape(-1, len(names))
    if "pkt_count" not in names:
        return X_attack[:0]
    pk = names.index("pkt_count")
    vol = [names.index(k) for k in _VOL_NAMES if k in names]
    port = [names.index(k) for k in _PORT_NAMES if k in names]
    out = []
    for x in X_attack:
        if x[pk] <= 0:
            continue
        for tgt in _AUG_VOLUMES:
            if tgt >= x[pk]:
                continue
            for t in _AUG_PORTS:
                y = x.copy()
                y[vol] *= tgt / x[pk]
                y[port] *= t
                out.append(y)
    return np.array(out).reshape(-1, len(names))


class ThreatModel:
    def __init__(self, cfg=None, feature_order=None):
        self.cfg = dict(DEFAULTS, **(cfg or {}))
        self.feature_order = list(feature_order or FEATURE_ORDER_V1)
        self.schema_version = schema_for(self.feature_order)
        self.xgb = None
        self.inc = None
        self._explainer = None

    # ------------------------------------------------------------- training
    def fit(self, X, y, augment=True):
        X = np.asarray(X, float); y = np.asarray(y, int)
        if augment:
            Xg = augment_scans(X[y == 1], self.feature_order)
            if len(Xg):
                X = np.vstack([X, Xg]); y = np.r_[y, np.ones(len(Xg), int)]
        self.n_fit_ = len(X)
        n_pos, n_neg = int(y.sum()), int((1 - y).sum())
        spw = n_neg / max(1, n_pos)                     # attacks are rare -> weight them up
        self.xgb = xgb.XGBClassifier(
            n_estimators=150, max_depth=2, learning_rate=0.1, colsample_bytree=0.3,
            scale_pos_weight=spw, eval_metric="logloss", random_state=SEED, n_jobs=1)
        self.xgb.fit(X, y)

        # Incremental model: logistic regression trained by SGD, can keep learning
        # one window at a time via partial_fit().
        self.inc = SGDClassifier(loss="log_loss", alpha=1e-4, learning_rate="constant", eta0=0.05,
                                 random_state=SEED)
        rng = np.random.RandomState(SEED)
        w = np.where(y == 1, spw, 1.0)
        for _ in range(200):
            idx = rng.permutation(len(X))
            self.inc.partial_fit(X[idx], y[idx], classes=[0, 1], sample_weight=w[idx])
        self._explainer = None
        return self

    # ------------------------------------------------------------ inference
    def p_xgb(self, X):
        return self.xgb.predict_proba(np.asarray(X, float))[:, 1]

    def p_inc(self, X):
        return self.inc.predict_proba(np.asarray(X, float))[:, 1]

    def fuse(self, px, pi):
        c = self.cfg
        return (c["w_xgb"] * px + c["w_inc"] * pi) / (c["w_xgb"] + c["w_inc"])

    def threat_probability(self, X):
        return self.fuse(self.p_xgb(X), self.p_inc(X))

    def label(self, p):
        c = self.cfg
        return "malicious" if p >= c["t_malicious"] else "suspicious" if p >= c["t_suspicious"] else "benign"

    # ---------------------------------------------------------- explanation
    def shap_values(self, X):
        """Per-feature contribution to the XGBoost output (log-odds).
        Returns (contribs [n, n_features], base_value)."""
        X = np.asarray(X, float)
        if HAVE_SHAP:
            try:
                if self._explainer is None:
                    self._explainer = shap.TreeExplainer(self.xgb)
                sv = np.asarray(self._explainer.shap_values(X))
                base = float(np.ravel(self._explainer.expected_value)[0])
                return sv, base
            except Exception:
                pass
        c = self.xgb.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)
        return c[:, :-1], float(c[0, -1])

    def feature_impact(self, x, top=5):
        sv, base = self.shap_values([x])
        sv = sv[0]
        order = np.argsort(-np.abs(sv))[:top]
        return [{"feature": self.feature_order[i], "value": round(float(x[i]), 6),
                 "impact": round(float(sv[i]), 4),
                 "direction": "raises risk" if sv[i] > 0 else "lowers risk"}
                for i in order if abs(sv[i]) > 1e-6], base

    def risk_score(self, p_fused):
        """Final risk score, 0-100."""
        return int(round(100 * float(p_fused)))

    # ------------------------------------------------------------- one call
    def assess(self, x, explain=True, top=5):
        x = np.asarray(x, float)
        px, pi = float(self.p_xgb([x])[0]), float(self.p_inc([x])[0])
        p = float(self.fuse(px, pi))
        out = {"p_xgboost": round(px, 6), "p_incremental": round(pi, 6),
               "threat_probability": round(p, 6), "threat_label": self.label(p),
               "risk_score": self.risk_score(p)}
        if explain:
            out["feature_impact"], out["shap_base_value"] = self.feature_impact(x, top)
        return out

    # ------------------------------------------------------ online learning
    def online_update(self, x, p_fused):
        """Self-training step for the incremental model on very confident windows.
        Returns the pseudo-label used, or None if the window was not confident enough."""
        c = self.cfg
        if p_fused <= c["online_lo"]:
            y = 0
        elif p_fused >= c["online_hi"]:
            y = 1
        else:
            return None
        self.inc.partial_fit(np.asarray([x], float), [y])
        return y

    # ---------------------------------------------------------- persistence
    def save(self, d):
        os.makedirs(d, exist_ok=True)
        self.xgb.save_model(os.path.join(d, "xgboost.json"))       # portable across xgboost versions
        dump(self.inc, os.path.join(d, "incremental.joblib"))
        with open(os.path.join(d, "config.json"), "w") as f:
            json.dump(dict(self.cfg, feature_order=self.feature_order,
                           schema_version=self.schema_version,
                           window_sec=WINDOW_SEC), f, indent=2)

    @classmethod
    def load(cls, d, incremental_file=None):
        with open(os.path.join(d, "config.json")) as f:
            cfg = json.load(f)
        m = cls({k: cfg[k] for k in DEFAULTS if k in cfg}, cfg.get("feature_order"))
        m.xgb = xgb.XGBClassifier()
        m.xgb.load_model(os.path.join(d, "xgboost.json"))
        m.inc = load(incremental_file or os.path.join(d, "incremental.joblib"))
        return m
