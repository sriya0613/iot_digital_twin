"""
collectors.py — the THREE collectors for Person 2's fingerprint pipeline.

Each collector takes a list of scapy packets belonging to one time window and
returns a flat dict of raw numeric features. The pipeline concatenates all three
into one raw feature vector per window, which is then normalized.

  collect_statistical  — volume + timing (how much / how fast)
  collect_protocol     — L3/L4 makeup (what kinds of packets)
  collect_service      — L7 / identity signals (what the device is doing)

FEATURE_ORDER fixes the vector layout so every window produces the same keys in
the same order, even for empty windows (zeros). Person C can rely on this order.
"""
from statistics import mean, pstdev

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether

# ---- fixed feature layout (do not reorder; append only, and bump schema) ----
STAT_FEATURES = [
    "pkt_count", "byte_count", "mean_pkt_size", "std_pkt_size",
    "mean_iat", "std_iat", "pkts_per_sec", "bytes_per_sec",
]
PROTO_FEATURES = [
    "frac_tcp", "frac_udp", "frac_icmp", "frac_arp", "frac_other",
    "n_unique_src_ports", "n_unique_dst_ports",
    "frac_syn", "frac_ack", "frac_rst", "mean_ttl",
]
SERVICE_FEATURES = [
    "n_dns_mdns", "n_dhcp", "n_arp_req", "n_arp_reply",
    "n_http", "n_https", "n_broadcast", "n_multicast", "distinct_l4_services",
]
FEATURE_ORDER = STAT_FEATURES + PROTO_FEATURES + SERVICE_FEATURES


def _pkt_len(p):
    try:
        return len(p)
    except Exception:
        return 0


def collect_statistical(pkts, window_dur):
    """Volumetric + timing features."""
    n = len(pkts)
    if n == 0:
        return {k: 0.0 for k in STAT_FEATURES}
    sizes = [_pkt_len(p) for p in pkts]
    times = sorted(float(p.time) for p in pkts)
    iats = [t2 - t1 for t1, t2 in zip(times, times[1:])] if n > 1 else [0.0]
    dur = window_dur if window_dur > 0 else max(1e-6, times[-1] - times[0])
    return {
        "pkt_count": float(n),
        "byte_count": float(sum(sizes)),
        "mean_pkt_size": float(mean(sizes)),
        "std_pkt_size": float(pstdev(sizes)) if n > 1 else 0.0,
        "mean_iat": float(mean(iats)),
        "std_iat": float(pstdev(iats)) if len(iats) > 1 else 0.0,
        "pkts_per_sec": float(n) / dur,
        "bytes_per_sec": float(sum(sizes)) / dur,
    }


def collect_protocol(pkts):
    """L3/L4 protocol makeup, port diversity, TCP flag mix, TTL."""
    n = len(pkts)
    if n == 0:
        return {k: 0.0 for k in PROTO_FEATURES}
    c_tcp = c_udp = c_icmp = c_arp = c_other = 0
    src_ports, dst_ports = set(), set()
    n_syn = n_ack = n_rst = 0
    ttls = []
    for p in pkts:
        if p.haslayer(TCP):
            c_tcp += 1
            t = p[TCP]
            src_ports.add(int(t.sport)); dst_ports.add(int(t.dport))
            f = str(t.flags)
            if "S" in f: n_syn += 1
            if "A" in f: n_ack += 1
            if "R" in f: n_rst += 1
        elif p.haslayer(UDP):
            c_udp += 1
            u = p[UDP]
            src_ports.add(int(u.sport)); dst_ports.add(int(u.dport))
        elif p.haslayer(ICMP):
            c_icmp += 1
        elif p.haslayer(ARP):
            c_arp += 1
        else:
            c_other += 1
        if p.haslayer(IP):
            ttls.append(int(p[IP].ttl))
    return {
        "frac_tcp": c_tcp / n,
        "frac_udp": c_udp / n,
        "frac_icmp": c_icmp / n,
        "frac_arp": c_arp / n,
        "frac_other": c_other / n,
        "n_unique_src_ports": float(len(src_ports)),
        "n_unique_dst_ports": float(len(dst_ports)),
        "frac_syn": n_syn / n,
        "frac_ack": n_ack / n,
        "frac_rst": n_rst / n,
        "mean_ttl": float(mean(ttls)) if ttls else 0.0,
    }


def collect_service(pkts):
    """L7 / identity signals: discovery, management, web, broadcast/multicast."""
    if not pkts:
        return {k: 0.0 for k in SERVICE_FEATURES}
    n_dns_mdns = n_dhcp = n_arp_req = n_arp_reply = 0
    n_http = n_https = n_broadcast = n_multicast = 0
    l4_services = set()
    for p in pkts:
        # discovery / mgmt
        if p.haslayer(UDP):
            sp, dp = int(p[UDP].sport), int(p[UDP].dport)
            if 53 in (sp, dp) or 5353 in (sp, dp) or p.haslayer(DNS):
                n_dns_mdns += 1
            if 67 in (sp, dp) or 68 in (sp, dp):
                n_dhcp += 1
            l4_services.add(("udp", dp))
        if p.haslayer(TCP):
            sp, dp = int(p[TCP].sport), int(p[TCP].dport)
            if 80 in (sp, dp) or 8080 in (sp, dp):
                n_http += 1
            if 443 in (sp, dp):
                n_https += 1
            l4_services.add(("tcp", dp))
        if p.haslayer(ARP):
            op = int(p[ARP].op)
            if op == 1: n_arp_req += 1
            elif op == 2: n_arp_reply += 1
        # L2 addressing
        if p.haslayer(Ether):
            dst = p[Ether].dst.lower()
            if dst == "ff:ff:ff:ff:ff:ff":
                n_broadcast += 1
            else:
                try:
                    first = int(dst.split(":")[0], 16)
                    if first & 0x01:
                        n_multicast += 1
                except Exception:
                    pass
    return {
        "n_dns_mdns": float(n_dns_mdns),
        "n_dhcp": float(n_dhcp),
        "n_arp_req": float(n_arp_req),
        "n_arp_reply": float(n_arp_reply),
        "n_http": float(n_http),
        "n_https": float(n_https),
        "n_broadcast": float(n_broadcast),
        "n_multicast": float(n_multicast),
        "distinct_l4_services": float(len(l4_services)),
    }


def collect_all(pkts, window_dur):
    """Run all three collectors and return one flat raw-feature dict."""
    out = {}
    out.update(collect_statistical(pkts, window_dur))
    out.update(collect_protocol(pkts))
    out.update(collect_service(pkts))
    # guarantee full, ordered coverage
    return {k: float(out.get(k, 0.0)) for k in FEATURE_ORDER}
