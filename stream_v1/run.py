#!/usr/bin/env python3
"""
run.py — Person 2 fingerprint pipeline CLI.

Two modes:

  build  — read a PCAP (or live capture to a fixed duration), fit the min-max
           scaler on the collected windows, label them against Person 1's
           manifest, and write a labeled fingerprint dataset (JSONL) + scaler.
           Use this to build the benign-vs-malware training set for Person C.

  stream — sniff mirror-host LIVE, apply a previously-fit scaler, label windows
           on the fly, and emit fingerprint records to stdout/file in real time.
           Use this to feed Person C during operation.

Examples:
  # build a dataset from a captured pcap, labeled by the manifest
  sudo python3 run.py build --pcap benign_run.pcap \
       --manifest run_manifest.jsonl --window 5 \
       --out dataset.jsonl --scaler scaler.json

  # stream live to Person C, reusing the scaler fit during build
  sudo python3 run.py stream --iface mirror-host --window 5 \
       --scaler scaler.json --manifest run_manifest.jsonl --out -
"""
import argparse
import json
import sys

from pipeline import (WindowAggregator, Labeler, fit_scaler, apply_scaler,
                      save_scaler, load_scaler, make_record, SCHEMA_VERSION)


def _out(path):
    return sys.stdout if path == "-" else open(path, "w")


def cmd_build(a):
    from scapy.all import PcapReader, sniff
    meta = {"device_ip": a.device_ip, "firmware_id": a.firmware_id, "mirror_if": a.iface or ""}
    labeler = Labeler(a.manifest)

    raw_windows = []  # (window_id, start, stop, raw)
    agg = WindowAggregator(a.window,
                           lambda wid, s, e, raw: raw_windows.append((wid, s, e, raw)))

    if a.pcap:
        with PcapReader(a.pcap) as pr:
            for p in pr:
                agg.add(p)
    else:
        print(f"[*] live-capturing {a.duration}s on {a.iface} ...", file=sys.stderr)
        pkts = sniff(iface=a.iface, timeout=a.duration, store=True)
        for p in pkts:
            agg.add(p)
    agg.flush()

    if not raw_windows:
        print("[!] no windows produced (empty capture?)", file=sys.stderr)
        sys.exit(1)

    # fit scaler on all raw windows, persist it for streaming later
    scaler = fit_scaler([r for _, _, _, r in raw_windows])
    save_scaler(scaler, a.scaler)

    n_by_label = {}
    with _out(a.out) as fo:
        for wid, s, e, raw in raw_windows:
            label, run_id = labeler.label((s + e) / 2.0)
            rec = make_record(wid, s, e, apply_scaler(raw, scaler), label, run_id, meta)
            fo.write(json.dumps(rec) + "\n")
            n_by_label[label] = n_by_label.get(label, 0) + 1

    print(f"[+] wrote {sum(n_by_label.values())} records to {a.out}", file=sys.stderr)
    print(f"[+] scaler saved to {a.scaler} (schema {SCHEMA_VERSION})", file=sys.stderr)
    print(f"[+] label breakdown: {n_by_label}", file=sys.stderr)


def cmd_stream(a):
    from scapy.all import sniff
    meta = {"device_ip": a.device_ip, "firmware_id": a.firmware_id, "mirror_if": a.iface}
    labeler = Labeler(a.manifest) if a.manifest else Labeler(None)
    scaler = load_scaler(a.scaler)
    fo = _out(a.out)

    def emit(wid, s, e, raw):
        label, run_id = labeler.label((s + e) / 2.0)
        rec = make_record(wid, s, e, apply_scaler(raw, scaler), label, run_id, meta)
        fo.write(json.dumps(rec) + "\n")
        fo.flush()  # real-time stream to Person C

    agg = WindowAggregator(a.window, emit)
    print(f"[*] streaming fingerprints from {a.iface} (window {a.window}s). Ctrl-C to stop.",
          file=sys.stderr)
    try:
        sniff(iface=a.iface, prn=agg.add, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        agg.flush()
        if fo is not sys.stdout:
            fo.close()


def main():
    ap = argparse.ArgumentParser(description="Person 2 fingerprint pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--window", type=float, default=5.0, help="window seconds (default 5)")
    common.add_argument("--manifest", help="Person 1 run_manifest.jsonl (for labels)")
    common.add_argument("--out", default="-", help="output JSONL path or - for stdout")
    common.add_argument("--scaler", default="scaler.json", help="scaler json path")
    common.add_argument("--device-ip", default="192.168.0.1")
    common.add_argument("--firmware-id", default="DIR-868L_revB_2-05b02")

    b = sub.add_parser("build", parents=[common], help="build labeled dataset")
    b.add_argument("--pcap", help="input pcap; omit to live-capture for --duration")
    b.add_argument("--iface", help="interface for live build (if no --pcap)")
    b.add_argument("--duration", type=int, default=60, help="live build seconds")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("stream", parents=[common], help="live stream to Person C")
    s.add_argument("--iface", default="mirror-host")
    s.set_defaults(func=cmd_stream)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
