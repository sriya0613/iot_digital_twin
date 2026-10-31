"""
pipeline.py — windowing, labeling, normalization, record assembly.

Flow:
  packets --> WindowAggregator (fixed time windows) --> raw feature dicts
          --> label each window by joining its midpoint into Person 1's manifest
          --> normalize (min-max), using a scaler fit on the dataset (persisted)
          --> emit fingerprint records (JSONL) for Person C
"""
import json

from collectors import collect_all, FEATURE_ORDER

SCHEMA_VERSION = "1.0.0"   # Person 2 OWNS this. Keep in sync with contracts/fingerprint.schema.json


# ----------------------------- labeling ------------------------------------
class Labeler:
    """Loads Person 1's run_manifest.jsonl and labels a window by its midpoint."""
    def __init__(self, manifest_path=None):
        self.windows = []  # (start, stop, label, run_id)
        if manifest_path:
            with open(manifest_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    self.windows.append((float(r["start_epoch"]),
                                         float(r["stop_epoch"]),
                                         r["label"], r["run_id"]))

    def label(self, mid_epoch):
        for start, stop, label, run_id in self.windows:
            if start <= mid_epoch < stop:
                return label, run_id
        return "unlabeled", None


# --------------------------- normalization ---------------------------------
def fit_scaler(raw_rows):
    """Fit min-max over a list of raw feature dicts. Returns {feat:[min,max]}."""
    scaler = {}
    for k in FEATURE_ORDER:
        vals = [row[k] for row in raw_rows] or [0.0]
        scaler[k] = [min(vals), max(vals)]
    return scaler


def apply_scaler(raw, scaler):
    """Min-max normalize one raw feature dict to [0,1] using a fitted scaler."""
    out = {}
    for k in FEATURE_ORDER:
        lo, hi = scaler.get(k, [0.0, 0.0])
        out[k] = 0.0 if hi <= lo else max(0.0, min(1.0, (raw[k] - lo) / (hi - lo)))
    return out


def save_scaler(scaler, path):
    with open(path, "w") as f:
        json.dump({"method": "minmax", "schema_version": SCHEMA_VERSION,
                   "ranges": scaler}, f, indent=2)


def load_scaler(path):
    with open(path) as f:
        return json.load(f)["ranges"]


# --------------------------- windowing -------------------------------------
class WindowAggregator:
    """
    Buckets packets into fixed [t0 + k*W, t0 + (k+1)*W) windows. Flushes a window
    when a packet from a later window arrives (packets are time-ordered on a live
    sniff and in a pcap). Call flush() at the end to emit the final window.
    """
    def __init__(self, window_sec, on_window):
        self.W = float(window_sec)
        self.on_window = on_window
        self.t0 = None
        self.cur_idx = None
        self.buf = []

    def add(self, pkt):
        t = float(pkt.time)
        if self.t0 is None:
            self.t0 = t
            self.cur_idx = 0
        idx = int((t - self.t0) // self.W)
        if idx != self.cur_idx:
            self._flush_current()
            # emit empty windows for any gap so the timeline is continuous
            for gap in range(self.cur_idx + 1, idx):
                self._emit_empty(gap)
            self.cur_idx = idx
        self.buf.append(pkt)

    def _win_bounds(self, idx):
        start = self.t0 + idx * self.W
        return start, start + self.W

    def _flush_current(self):
        if self.cur_idx is None:
            return
        start, stop = self._win_bounds(self.cur_idx)
        raw = collect_all(self.buf, self.W)
        self.on_window(self.cur_idx, start, stop, raw)
        self.buf = []

    def _emit_empty(self, idx):
        start, stop = self._win_bounds(idx)
        raw = collect_all([], self.W)
        self.on_window(idx, start, stop, raw)

    def flush(self):
        self._flush_current()


# ------------------------- record assembly ---------------------------------
def make_record(window_id, start, stop, features_norm, label, run_id, meta):
    return {
        "schema_version": SCHEMA_VERSION,
        "window_id": window_id,
        "window_start_epoch": round(start, 6),
        "window_end_epoch": round(stop, 6),
        "device_ip": meta.get("device_ip", ""),
        "firmware_id": meta.get("firmware_id", ""),
        "mirror_if": meta.get("mirror_if", ""),
        "label": label,
        "run_id": run_id,
        "features": {k: round(features_norm[k], 6) for k in FEATURE_ORDER},
        "meta": {"normalization": "minmax", "n_features": len(FEATURE_ORDER)},
    }
