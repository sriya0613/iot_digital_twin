"""
pipeline.py — windowing, labeling, normalization, record assembly (schema v2.0.0).

Flow:
  packets + syscall events + energy samples
      --> WindowAggregator (fixed time windows)   --> raw feature dicts
      --> label each window against Person 1's manifest
      --> normalize (min-max) with a scaler fit on the dataset
      --> emit fingerprint records (JSONL) for Person C
"""
import json
import threading
import time

from collectors import collect_all, FEATURE_ORDER

SCHEMA_VERSION = "2.0.0"


# ----------------------------- labeling ------------------------------------
class Labeler:
    """Loads run_manifest.jsonl and labels a window by the run it overlaps most.
    A window needs at least MIN_OVERLAP seconds inside a run to take its label."""
    MIN_OVERLAP = 0.5

    def __init__(self, manifest_path=None):
        self.windows = []  # (start, stop, label, run_id)
        if manifest_path:
            with open(manifest_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    self.windows.append((float(r["start_epoch"]), float(r["stop_epoch"]),
                                         r["label"], r.get("run_id"), r.get("attack_class", "")))

    def label(self, start, stop):
        """(label, run_id, attack_class). An attack run takes priority over a benign run
        that overlaps the same window; within a kind, the larger overlap wins."""
        best = {}
        for s, e, label, run_id, aclass in self.windows:
            ov = min(stop, e) - max(start, s)
            # a run shorter than a second (a fast scan) counts if half of it is in the window
            if ov <= 0 or ov < min(self.MIN_OVERLAP, 0.5 * (e - s)):
                continue
            kind = "benign" if label == "benign" else "other"
            if kind not in best or ov > best[kind][0]:
                best[kind] = (ov, label, run_id, aclass)
        for kind in ("other", "benign"):
            if kind in best:
                return best[kind][1], best[kind][2], best[kind][3]
        return "unlabeled", None, ""


# --------------------------- normalization ---------------------------------
def fit_scaler(raw_rows):
    """Fit min-max over a list of raw feature dicts. Returns {feat:[min,max]}."""
    scaler = {}
    for k in FEATURE_ORDER:
        vals = [row.get(k, 0.0) for row in raw_rows] or [0.0]
        scaler[k] = [min(vals), max(vals)]
    return scaler


def apply_scaler(raw, scaler):
    """Min-max normalize one raw feature dict to [0,1]. A feature the scaler does
    not know (e.g. a v1 scaler and the new syscall/energy features) becomes 0."""
    out = {}
    for k in FEATURE_ORDER:
        lo, hi = scaler.get(k, [0.0, 0.0])
        out[k] = 0.0 if hi <= lo else max(0.0, min(1.0, (raw.get(k, 0.0) - lo) / (hi - lo)))
    return out


def save_scaler(scaler, path):
    with open(path, "w") as f:
        json.dump({"method": "minmax", "schema_version": SCHEMA_VERSION, "ranges": scaler}, f, indent=2)


def load_scaler(path):
    with open(path) as f:
        return json.load(f)["ranges"]


# --------------------------- windowing -------------------------------------
class WindowAggregator:
    """
    Buckets packets, syscall events and energy samples into fixed
    [t0 + k*W, t0 + (k+1)*W) windows and calls on_window(idx, start, stop, raw)
    for each window in order, including empty ones.

    Two ways to close a window:
      * offline (pcap): a window closes when an item from a later window arrives;
        call flush() at the end.
      * live: call start() once and tick() regularly — a window closes as soon as
        its time is over, whether or not any packet arrived afterwards.
    """

    def __init__(self, window_sec, on_window):
        self.W = float(window_sec)
        self.on_window = on_window
        self.t0 = None
        self.next_idx = 0          # next window to emit
        self.buf = {}              # idx -> {"pkts": [], "sys": [], "en": []}
        self.late = 0
        self.lock = threading.RLock()

    def start(self, t0=None):
        with self.lock:
            if self.t0 is None:
                self.t0 = time.time() if t0 is None else float(t0)

    def _slot(self, ts):
        if self.t0 is None:
            self.t0 = ts
        idx = int((ts - self.t0) // self.W)
        if idx < self.next_idx:
            self.late += 1
            return None, idx
        return self.buf.setdefault(idx, {"pkts": [], "sys": [], "en": []}), idx

    def add(self, pkt, live=False):
        """Add a packet. Offline, a packet from a later window closes earlier ones."""
        with self.lock:
            slot, idx = self._slot(float(pkt.time))
            if slot is None:
                return
            slot["pkts"].append(pkt)
            if not live:
                self._emit_until(idx)

    def add_syscall(self, ev):
        with self.lock:
            slot, _ = self._slot(float(ev["ts"]))
            if slot is not None:
                slot["sys"].append(ev)

    def add_energy(self, sample):
        with self.lock:
            # a sample covers the dt seconds before its timestamp
            slot, _ = self._slot(float(sample["ts"]) - 0.5 * float(sample["dt"]))
            if slot is not None:
                slot["en"].append(sample)

    def _emit_until(self, idx):
        """Emit every window with index < idx."""
        while self.next_idx < idx:
            i = self.next_idx
            slot = self.buf.pop(i, {"pkts": [], "sys": [], "en": []})
            start = self.t0 + i * self.W
            raw = collect_all(slot["pkts"], self.W, slot["sys"], slot["en"])
            self.next_idx = i + 1
            self.on_window(i, start, start + self.W, raw)

    def tick(self, now=None, slack=0.3):
        """Live: emit every window that ended at least `slack` seconds ago."""
        with self.lock:
            if self.t0 is None:
                return
            now = time.time() if now is None else now
            self._emit_until(int((now - slack - self.t0) // self.W))

    def flush(self):
        """Emit everything still buffered (end of a pcap, or shutdown)."""
        with self.lock:
            if self.buf:
                self._emit_until(max(self.buf) + 1)


# ------------------------- record assembly ---------------------------------
def make_record(window_id, start, stop, features_norm, label, run_id, meta, attack_class=""):
    return {
        "schema_version": SCHEMA_VERSION,
        "window_id": window_id,
        "window_start_epoch": round(start, 6),
        "window_end_epoch": round(stop, 6),
        "device_ip": meta.get("device_ip", ""),
        "firmware_id": meta.get("firmware_id", ""),
        "mirror_if": meta.get("mirror_if", ""),
        "label": label,
        "attack_class": attack_class,
        "run_id": run_id,
        "features": {k: round(features_norm[k], 6) for k in FEATURE_ORDER},
        "meta": {"normalization": "minmax", "n_features": len(FEATURE_ORDER),
                 "monitors": meta.get("monitors", {})},
    }
