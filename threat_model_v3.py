"""threat_model_v3.py — the full hybrid detector (final version).

It wraps the proven binary ThreatModel (threat_model.py) and adds the three pieces the
architecture diagram asks for, each on top of the working core so the live loop still runs:

    hybrid        anomaly autoencoder (unknown threats) + supervised XGBoost/incremental (known)
    multi-class   a second XGBoost head names the attack type: scan | bruteforce | dos | beacon
    blended risk  risk score = blend of (classifier confidence, anomaly score, class severity)

    Fingerprint ─┬─> binary core  ─> p_attack (known-threat confidence) ─┐
                 ├─> autoencoder  ─> reconstruction error -> anomaly    ─┼─> blended risk 0-100
                 └─> multi-class  ─> attack_class + per-class prob       ─┘  + threat label + SHAP

The autoencoder is a small sklearn MLP trained on BENIGN windows only; a window the model
cannot reconstruct well is anomalous, which catches attacks no label was seen for.
The incremental model is River's Adaptive Random Forest when River is installed, else the
binary core's SGD model (both support one-window-at-a-time updates for the feedback loop).
"""
import json
import os

import numpy as np
from joblib import dump, load
from sklearn.neural_network import MLPRegressor

import xgboost as xgb
from common import FEATURE_ORDER_V2, monitor_of, schema_for
from threat_model import ThreatModel, SEED

try:
    from river import forest as river_forest, preprocessing as river_pre
    HAVE_RIVER = True
except Exception:
    HAVE_RIVER = False

# How dangerous each attack type is, 0-1. Used in the blended risk score so a DoS scores
# higher than a scan at the same model confidence. Tunable; documented in the model card.
SEVERITY = {"benign": 0.0, "scan": 0.4, "beacon": 0.5, "bruteforce": 0.7, "dos": 0.9}
ATTACK_CLASSES = ["scan", "bruteforce", "dos", "beacon"]

RISK_W = {"confidence": 0.5, "anomaly": 0.2, "severity": 0.3}   # blend weights, sum to 1


class HybridModel:
    def __init__(self, cfg=None, feature_order=None):
        self.feature_order = list(feature_order or FEATURE_ORDER_V2)
        self.schema_version = schema_for(self.feature_order)
        self.core = ThreatModel(cfg, self.feature_order)   # binary attack/not-attack + SHAP
        self.ae = None                                      # autoencoder (benign-only)
        self.ae_err_ref = 1.0                               # reconstruction error that maps to anomaly=1
        self.mc = None                                      # multi-class head (XGBoost)
        self.mc_classes = []                                # class order of mc
        self.river = None                                   # optional online model

    # ------------------------------------------------------------- training
    def fit(self, X, y_bin, classes, augment=True):
        """X: [n, F]. y_bin: 0/1 attack. classes: attack-type string per row ('' / 'benign' for normal)."""
        X = np.asarray(X, float)
        y_bin = np.asarray(y_bin, int)
        classes = np.asarray(classes, dtype=object)

        # 1) binary core (XGBoost + incremental + SHAP) — unchanged, proven
        self.core.fit(X, y_bin, augment=augment)

        # 2) autoencoder on benign windows only -> reconstruction error = anomaly
        Xben = X[y_bin == 0]
        if len(Xben) >= 10:
            h = max(2, X.shape[1] // 3)
            self.ae = MLPRegressor(hidden_layer_sizes=(h,), activation="relu", solver="adam",
                                   max_iter=600, random_state=SEED)
            self.ae.fit(Xben, Xben)
            err = self._recon_err(Xben)
            self.ae_err_ref = float(np.percentile(err, 99)) or 1.0   # 95th pct of benign error -> anomaly 1.0

        # 3) multi-class head: name the attack type (trained on attack windows only)
        atk = np.array([c in SEVERITY and c not in ("", "benign") for c in classes])
        if atk.sum() >= len(ATTACK_CLASSES):
            self.mc_classes = sorted(set(classes[atk]))
            ci = {c: i for i, c in enumerate(self.mc_classes)}
            ymc = np.array([ci[c] for c in classes[atk]])
            self.mc = xgb.XGBClassifier(n_estimators=200, max_depth=3, learning_rate=0.1,
                                        subsample=0.9, colsample_bytree=0.5,
                                        objective="multi:softprob", num_class=len(self.mc_classes),
                                        eval_metric="mlogloss", random_state=SEED, n_jobs=1)
            self.mc.fit(X[atk], ymc)

        # 4) optional River online model (feedback loop); mirrors the binary task
        if HAVE_RIVER:
            self.river = river_pre.StandardScaler() | river_forest.ARFClassifier(n_models=10, seed=SEED)
            for xi, yi in zip(X, y_bin):
                self.river.learn_one({k: float(v) for k, v in zip(self.feature_order, xi)}, int(yi))
        return self

    # drop-in compatibility with the binary detector (live_detector.py)
    @property
    def cfg(self):
        return self.core.cfg

    @property
    def inc(self):
        return self.core.inc

    # ------------------------------------------------------------ inference
    def _recon_err(self, X):
        X = np.asarray(X, float)
        return np.mean((X - self.ae.predict(X)) ** 2, axis=1)

    def anomaly_score(self, X):
        if self.ae is None:
            return np.zeros(len(np.asarray(X, float)))
        return np.clip(self._recon_err(X) / max(self.ae_err_ref, 1e-9), 0.0, 1.0)

    def predict_class(self, x):
        """(attack_class, prob) for one window, or (None, 0) if no multi-class head."""
        if self.mc is None:
            return None, 0.0
        p = self.mc.predict_proba(np.asarray([x], float))[0]
        i = int(np.argmax(p))
        return self.mc_classes[i], float(p[i])

    def blended_risk(self, confidence, anomaly, severity):
        w = RISK_W
        r = w["confidence"] * confidence + w["anomaly"] * anomaly + w["severity"] * severity * confidence
        return int(round(100 * float(np.clip(r, 0, 1))))

    def assess(self, x, explain=True, top=5):
        x = np.asarray(x, float)
        base = self.core.assess(x, explain=explain, top=top)   # p_xgboost, p_incremental, threat_probability, label, SHAP
        conf = base["threat_probability"]
        anom = float(self.anomaly_score([x])[0])
        label = base["threat_label"]
        aclass, aprob = (None, 0.0)
        if label != "benign":
            aclass, aprob = self.predict_class(x)
        sev = SEVERITY.get(aclass, 0.0) if aclass else 0.0
        base["anomaly_score"] = round(anom, 6)
        base["attack_class"] = aclass
        base["attack_class_prob"] = round(aprob, 6)
        base["risk_score"] = self.blended_risk(conf, anom, sev)   # override binary risk with the blended one
        base["risk_components"] = {"confidence": round(conf, 4), "anomaly": round(anom, 4),
                                   "severity": sev, "weights": RISK_W}
        if explain and base.get("feature_impact"):
            for e in base["feature_impact"]:
                e["monitor"] = monitor_of(e["feature"])
        return base

    # ------------------------------------------------------ online learning
    def online_update(self, x, p_fused, confirmed_label=None):
        """Feedback loop. Updates the incremental model(s) on a confirmed window.
        confirmed_label (0/1) from the threat DB is used when given, else the confident-window rule."""
        y = self.core.online_update(x, p_fused) if confirmed_label is None else confirmed_label
        if confirmed_label is not None:
            self.core.inc.partial_fit(np.asarray([x], float), [int(confirmed_label)])
            y = confirmed_label
        if self.river is not None and y is not None:
            self.river.learn_one({k: float(v) for k, v in zip(self.feature_order, x)}, int(y))
        return y

    # ---------------------------------------------------------- persistence
    def save(self, d):
        os.makedirs(d, exist_ok=True)
        self.core.save(d)                                    # xgboost.json, incremental.joblib, config.json
        if self.ae is not None:
            dump({"ae": self.ae, "ref": self.ae_err_ref}, os.path.join(d, "autoencoder.joblib"))
        if self.mc is not None:
            self.mc.save_model(os.path.join(d, "multiclass.json"))
            with open(os.path.join(d, "multiclass_classes.json"), "w") as f:
                json.dump({"classes": self.mc_classes, "severity": SEVERITY, "risk_weights": RISK_W}, f, indent=2)

    @classmethod
    def load(cls, d):
        core = ThreatModel.load(d)
        m = cls(None, core.feature_order)
        m.core = core
        ap = os.path.join(d, "autoencoder.joblib")
        if os.path.exists(ap):
            o = load(ap); m.ae = o["ae"]; m.ae_err_ref = o["ref"]
        mp = os.path.join(d, "multiclass.json")
        if os.path.exists(mp):
            m.mc = xgb.XGBClassifier(); m.mc.load_model(mp)
            with open(os.path.join(d, "multiclass_classes.json")) as f:
                m.mc_classes = json.load(f)["classes"]
        return m
