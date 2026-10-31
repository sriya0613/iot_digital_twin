#!/usr/bin/env python3
"""
run.py — Person 2 fingerprint pipeline CLI (schema v2.0.0: network + syscall + energy).

Modes
  record  LIVE: run the three monitors and write RAW (un-normalised) windows to a
          file. Use this while you play benign traffic and attacks at the twin.
  build   Turn recorded raw windows (or a pcap) into a labeled, normalised dataset
          and fit the scaler. Labels come from run_manifest.jsonl (label_run.py).
  stream  LIVE: run the three monitors, normalise with a fitted scaler and print
          one fingerprint record per window for Person C.

The three monitors
  network  scapy sniffer on --iface                       (always on)
  syscall  follows --syscall-log (Firmadyne kernel lines in the QEMU serial log,
           or strace output)                              (off without --syscall-log)
  energy   samples the emulator process (--emulator-pid auto|PID|none) once a
           second: CPU time, I/O operations, page faults, plus network bytes

Examples
  # 1. record ~10 minutes of all three monitors
  sudo python3 run.py record --iface tap1_0.1 \\
       --syscall-log ~/firmae/FirmAE/scratch/1/qemu.final.serial.log --out raw_windows.jsonl

  # 2. build the dataset + scaler
  python3 run.py build --raw raw_windows.jsonl --manifest run_manifest.jsonl \\
       --out dataset_v2.jsonl --scaler scaler_v2.json

  # 3. live stream to Person C
  sudo python3 run.py stream --iface tap1_0.1 --scaler scaler_v2.json \\
       --syscall-log ~/firmae/FirmAE/scratch/1/qemu.final.serial.log --out -

  # network-only dataset from a pcap still works
  python3 run.py build --pcap run.pcap --manifest run_manifest.jsonl --out dataset.jsonl --scaler scaler.json
"""
import argparse
import json
import os
import sys
import threading
import time

from pipeline import (WindowAggregator, Labeler, fit_scaler, apply_scaler,
                      save_scaler, load_scaler, make_record, SCHEMA_VERSION)
from monitors import SyscallTail, EnergySampler


def _out(path, mode="w"):
    return sys.stdout if path == "-" else open(path, mode)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ------------------------------ live capture ---------------------------------
def run_live(a, on_window):
    """Start the three monitors and call on_window(idx, start, stop, raw, monitors)
    for every finished window until Ctrl-C / --duration / the interface goes away."""
    from scapy.all import sniff

    status = {"network": a.iface, "syscall": "off", "energy": "off"}
    agg = WindowAggregator(a.window, lambda i, s, e, raw: on_window(i, s, e, raw, dict(status)))

    tail = sampler = None
    if a.syscall_log:
        tail = SyscallTail(os.path.expanduser(a.syscall_log), agg.add_syscall)
        tail.start()
        status["syscall"] = "log"
    if a.emulator_pid != "none":
        sampler = EnergySampler(agg.add_energy, pid=a.emulator_pid, pattern=a.emulator_name)
        sampler.start()
        status["energy"] = "emulator"

    def on_packet(p):
        if sampler is not None:
            try:
                sampler.add_net(len(p))
            except Exception:
                pass
        agg.add(p, live=True)

    stop = threading.Event()

    def ticker():
        while not stop.wait(0.25):
            if sampler is not None:      # say honestly whether the emulator was found
                status["energy"] = "emulator" if sampler.pid else "network-only (emulator not found)"
            agg.tick()

    agg.start()
    t = threading.Thread(target=ticker, daemon=True)
    t.start()
    log("[*] monitors: network=%s  syscall=%s  energy=%s  (window %ss). Ctrl-C to stop." % (
        a.iface, a.syscall_log or "off", "emulator pid " + str(a.emulator_pid) if sampler else "off", a.window))
    try:
        sniff(iface=a.iface, prn=on_packet, store=False, timeout=a.duration or None)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join(timeout=2)
        agg.tick()
        if tail is not None:
            tail.stop()
            log("[*] syscall monitor: %d events from %d lines" % (tail.n_events, tail.n_lines))
            if tail.n_lines and not tail.n_events:
                log("[!] the syscall log had lines but none looked like a system call - check its format")
            if not tail.n_lines:
                log("[!] the syscall log produced no new lines - syscall features are all zero")
        if sampler is not None:
            sampler.stop()
            log("[*] energy monitor: %d samples, %d with emulator CPU/IO data" % (
                sampler.n_samples, sampler.n_with_pid))
            if sampler.n_samples and not sampler.n_with_pid:
                log("[!] no emulator process found - energy used the network term only")


def cmd_record(a):
    fo = _out(a.out, "a" if a.append else "w")
    n = [0]

    def on_window(i, s, e, raw, monitors):
        fo.write(json.dumps({"window_start_epoch": round(s, 6), "window_end_epoch": round(e, 6),
                             "raw": raw, "monitors": monitors}) + "\n")
        fo.flush()
        n[0] += 1
        if fo is not sys.stdout:
            log("  win %-4d pkts %-6d syscalls %-6d power %.2f W" % (
                i, raw["pkt_count"], raw["sys_count"], raw["energy_mean_power"]))

    try:
        run_live(a, on_window)
    finally:
        if fo is not sys.stdout:
            fo.close()
        log("[+] recorded %d raw windows to %s" % (n[0], a.out))


def cmd_stream(a):
    meta = {"device_ip": a.device_ip, "firmware_id": a.firmware_id, "mirror_if": a.iface}
    labeler = Labeler(a.manifest) if a.manifest else Labeler(None)
    scaler = load_scaler(a.scaler)
    fo = _out(a.out)

    def on_window(i, s, e, raw, monitors):
        label, run_id, attack_class = labeler.label(s, e)
        rec = make_record(i, s, e, apply_scaler(raw, scaler), label, run_id, dict(meta, monitors=monitors), attack_class)
        fo.write(json.dumps(rec) + "\n")
        fo.flush()                       # real-time stream to Person C

    try:
        run_live(a, on_window)
    finally:
        if fo is not sys.stdout:
            fo.close()


# --------------------------------- build ---------------------------------------
def cmd_build(a):
    meta = {"device_ip": a.device_ip, "firmware_id": a.firmware_id, "mirror_if": a.iface or ""}
    labeler = Labeler(a.manifest)
    rows = []      # (start, stop, raw, monitors)

    if a.raw:
        for path in a.raw:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        r = json.loads(line)
                        rows.append((r["window_start_epoch"], r["window_end_epoch"], r["raw"],
                                     r.get("monitors", {})))
        rows.sort(key=lambda r: r[0])
    elif a.pcap:
        from scapy.all import PcapReader
        mon = {"network": "pcap", "syscall": "off", "energy": "network-only (pcap)"}
        agg = WindowAggregator(a.window, lambda i, s, e, raw: rows.append((s, e, raw, mon)))
        with PcapReader(a.pcap) as pr:
            for p in pr:
                agg.add(p)
        agg.flush()
    else:
        sys.exit("build needs --raw FILE [FILE ...] (from 'record') or --pcap FILE")

    if not rows:
        sys.exit("[!] no windows to build from")

    scaler = fit_scaler([r[2] for r in rows])
    save_scaler(scaler, a.scaler)

    n_by_label = {}
    with _out(a.out) as fo:
        for wid, (s, e, raw, monitors) in enumerate(rows):
            label, run_id, attack_class = labeler.label(s, e)
            rec = make_record(wid, s, e, apply_scaler(raw, scaler), label, run_id, dict(meta, monitors=monitors), attack_class)
            fo.write(json.dumps(rec) + "\n")
            n_by_label[label] = n_by_label.get(label, 0) + 1

    dead = [k for k, (lo, hi) in scaler.items() if hi <= lo]
    log("[+] wrote %d records to %s" % (len(rows), a.out))
    log("[+] scaler saved to %s (schema %s)" % (a.scaler, SCHEMA_VERSION))
    log("[+] label breakdown: %s" % n_by_label)
    if any(k.startswith("sys_") for k in dead) and all(k in dead for k in scaler if k.startswith("sys_")):
        log("[!] every syscall feature is constant: the syscall monitor recorded nothing")
    if "energy_cpu_util" in dead:
        log("[!] energy_cpu_util is constant: the energy monitor never saw the emulator process")


def main():
    ap = argparse.ArgumentParser(description="Person 2 fingerprint pipeline (network + syscall + energy)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--window", type=float, default=5.0, help="window seconds (default 5)")
    common.add_argument("--manifest", help="run_manifest.jsonl (for labels)")
    common.add_argument("--out", default="-", help="output JSONL path or - for stdout")
    common.add_argument("--scaler", default="scaler.json", help="scaler json path")
    common.add_argument("--device-ip", default="192.168.0.1")
    common.add_argument("--firmware-id", default="DIR-868L_revB_2-05b02")

    live = argparse.ArgumentParser(add_help=False)
    live.add_argument("--iface", default="tap1_0.1")
    live.add_argument("--syscall-log", help="text log of guest system calls to follow (serial log or strace output)")
    live.add_argument("--emulator-pid", default="auto", help="auto | PID | none  (process sampled by the energy monitor)")
    live.add_argument("--emulator-name", default="qemu-system", help="process name to look for with --emulator-pid auto")
    live.add_argument("--duration", type=float, default=0, help="stop after this many seconds (0 = until Ctrl-C)")

    r = sub.add_parser("record", parents=[common, live], help="live capture of raw windows")
    r.add_argument("--append", action="store_true", help="append to --out instead of overwriting")
    r.set_defaults(func=cmd_record)

    b = sub.add_parser("build", parents=[common], help="build labeled dataset + scaler")
    b.add_argument("--raw", nargs="+", help="raw window file(s) written by 'record'")
    b.add_argument("--pcap", help="input pcap (network features only)")
    b.add_argument("--iface", help=argparse.SUPPRESS)
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("stream", parents=[common, live], help="live stream to Person C")
    s.set_defaults(func=cmd_stream)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
