"""common.py — shared helpers for the detector (ML detection + auto-heal).

Contract with the fingerprint stream: one JSONL record per 5-second window.
  schema 1.0.0 : 28 network features
  schema 2.0.0 : the same 28 network features + 11 syscall + 6 energy features
All feature values are min-max normalised to [0,1] (see contracts/).
"""
import json

WINDOW_SEC = 5

# Same order as collectors.FEATURE_ORDER in the stream code.
FEATURE_ORDER_V1 = [
    "pkt_count", "byte_count", "mean_pkt_size", "std_pkt_size",
    "mean_iat", "std_iat", "pkts_per_sec", "bytes_per_sec",
    "frac_tcp", "frac_udp", "frac_icmp", "frac_arp", "frac_other",
    "n_unique_src_ports", "n_unique_dst_ports",
    "frac_syn", "frac_ack", "frac_rst", "mean_ttl",
    "n_dns_mdns", "n_dhcp", "n_arp_req", "n_arp_reply",
    "n_http", "n_https", "n_broadcast", "n_multicast", "distinct_l4_services",
]
SYSCALL_FEATURES = [
    "sys_count", "sys_per_sec", "sys_unique", "sys_rare_count", "sys_entropy",
    "sys_frac_net", "sys_frac_file", "sys_frac_proc", "sys_n_exec",
    "sys_ngram_unique", "sys_n_pids",
]
ENERGY_FEATURES = [
    "energy_mean_power", "energy_peak_power", "energy_j",
    "energy_cpu_util", "energy_io_ops", "energy_per_syscall",
]
FEATURE_ORDER_V2 = FEATURE_ORDER_V1 + SYSCALL_FEATURES + ENERGY_FEATURES

SCHEMAS = {"1.0.0": FEATURE_ORDER_V1, "2.0.0": FEATURE_ORDER_V2}
NETWORK_FEATURES = FEATURE_ORDER_V1
FEATURE_ORDER = FEATURE_ORDER_V1     # kept for older imports
SCHEMA_VERSION = "1.0.0"             # kept for older imports


def monitor_of(feature):
    """Which of the three monitors a feature comes from."""
    return "syscall" if feature.startswith("sys_") else "energy" if feature.startswith("energy_") else "network"


def schema_for(feature_order):
    for ver, order in SCHEMAS.items():
        if list(order) == list(feature_order):
            return ver
    return "custom"


class BadRecord(ValueError):
    pass


def check_record(rec, schema_version=None, feature_order=None):
    """Light contract check (no jsonschema dependency needed at run time).
    With schema_version / feature_order given, the record must match what the
    trained model expects."""
    if not isinstance(rec, dict):
        raise BadRecord("record is not a JSON object")
    ver = rec.get("schema_version")
    if ver not in SCHEMAS:
        raise BadRecord("schema_version %r is not one of %s" % (ver, sorted(SCHEMAS)))
    if schema_version is not None and ver != schema_version:
        raise BadRecord("record is schema %s but the model was trained on %s" % (ver, schema_version))
    feats = rec.get("features")
    if not isinstance(feats, dict):
        raise BadRecord("missing features")
    missing = [k for k in (feature_order or SCHEMAS[ver]) if k not in feats]
    if missing:
        raise BadRecord("missing features: %s" % ", ".join(missing[:6]))
    return rec


def to_vector(rec, feature_order=None):
    f = rec["features"]
    return [float(f[k]) for k in (feature_order or SCHEMAS[rec["schema_version"]])]


def load_records(path):
    out = []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(check_record(json.loads(line)))
            except (ValueError, BadRecord) as e:
                raise SystemExit("%s line %d: %s" % (path, n, e))
    if len({r["schema_version"] for r in out}) > 1:
        raise SystemExit("%s mixes schema versions" % path)
    return out
