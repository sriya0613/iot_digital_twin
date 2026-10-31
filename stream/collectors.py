"""
collectors.py — the THREE monitors' feature collectors (fingerprint schema v2.0.0).

Each collector turns what one monitor saw during one time window into a flat
dict of raw numeric features. The pipeline joins all three into one vector per
window and normalises it.

  network  (28)  collect_statistical / collect_protocol / collect_service
                 from the sniffed packets — unchanged from schema v1.0.0
  syscall  (11)  collect_syscall   from the guest's system-call events
  energy    (6)  collect_energy    from the virtual energy model

FEATURE_ORDER fixes the vector layout. The first 28 names are exactly the
v1.0.0 features in their old order, so a v1 model can still read a v2 record.
"""
import math
from collections import Counter
from statistics import mean, pstdev

try:                                   # scapy is only needed for the network collectors
    from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Ether
except Exception:                      # pragma: no cover
    IP = TCP = UDP = ICMP = ARP = DNS = Ether = None

# ---- fixed feature layout (append only, and bump the schema) ----------------
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
NETWORK_FEATURES = STAT_FEATURES + PROTO_FEATURES + SERVICE_FEATURES
SYSCALL_FEATURES = [
    "sys_count", "sys_per_sec", "sys_unique", "sys_rare_count", "sys_entropy",
    "sys_frac_net", "sys_frac_file", "sys_frac_proc", "sys_n_exec",
    "sys_ngram_unique", "sys_n_pids",
]
ENERGY_FEATURES = [
    "energy_mean_power", "energy_peak_power", "energy_j",
    "energy_cpu_util", "energy_io_ops", "energy_per_syscall",
]
FEATURE_ORDER = NETWORK_FEATURES + SYSCALL_FEATURES + ENERGY_FEATURES


# =============================== network ====================================
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
        if p.haslayer(Ether):
            dst = p[Ether].dst.lower()
            if dst == "ff:ff:ff:ff:ff:ff":
                n_broadcast += 1
            else:
                try:
                    if int(dst.split(":")[0], 16) & 0x01:
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


# =============================== syscall ====================================
# A call outside this set counts as "rare" (same list as monitors/syscall_monitor.py
# in the team repo, plus the kernel-hook names the Firmadyne kernel logs).
COMMON_SYSCALLS = {
    "read", "write", "open", "openat", "close", "stat", "fstat", "lstat", "poll", "select",
    "mmap", "munmap", "brk", "ioctl", "socket", "connect", "accept", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "clone", "fork", "execve", "exit", "exit_group", "bind",
    "nanosleep", "gettimeofday", "time", "rt_sigaction", "rt_sigprocmask", "futex", "lseek",
    "fcntl", "wait4", "getpid", "access", "mprotect", "newselect", "epoll_wait", "clock_gettime",
    "setsockopt", "getsockopt", "listen",
}
NET_SYSCALLS = {"socket", "bind", "connect", "accept", "accept4", "listen", "sendto", "recvfrom",
                "sendmsg", "recvmsg", "send", "recv", "shutdown", "setsockopt", "getsockopt",
                "socketpair", "getsockname", "getpeername"}
FILE_SYSCALLS = {"open", "openat", "read", "write", "close", "unlink", "unlinkat", "mknod", "stat",
                 "fstat", "lstat", "mount", "umount", "rename", "mkdir", "rmdir", "chmod", "chown",
                 "lseek", "readv", "writev", "pread64", "pwrite64", "access", "creat", "symlink",
                 "link", "truncate", "getdents", "getdents64"}
PROC_SYSCALLS = {"execve", "fork", "vfork", "clone", "exit", "exit_group", "kill", "wait4",
                 "waitpid", "reboot", "ptrace", "setuid", "setgid", "prctl", "tgkill"}


def collect_syscall(events, window_dur):
    """events: list of {"ts", "pid", "syscall"} seen in this window."""
    n = len(events)
    if n == 0:
        return {k: 0.0 for k in SYSCALL_FEATURES}
    names = [e["syscall"] for e in events]
    freq = Counter(names)
    probs = [c / n for c in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    ngrams = {tuple(names[i:i + 3]) for i in range(n - 2)}
    dur = window_dur if window_dur > 0 else 1.0
    return {
        "sys_count": float(n),
        "sys_per_sec": n / dur,
        "sys_unique": float(len(freq)),
        "sys_rare_count": float(sum(c for s, c in freq.items() if s not in COMMON_SYSCALLS)),
        "sys_entropy": float(entropy),
        "sys_frac_net": sum(c for s, c in freq.items() if s in NET_SYSCALLS) / n,
        "sys_frac_file": sum(c for s, c in freq.items() if s in FILE_SYSCALLS) / n,
        "sys_frac_proc": sum(c for s, c in freq.items() if s in PROC_SYSCALLS) / n,
        "sys_n_exec": float(freq.get("execve", 0)),
        "sys_ngram_unique": float(len(ngrams)),
        "sys_n_pids": float(len({e.get("pid", 0) for e in events})),
    }


# =============================== energy =====================================
# Virtual energy model. A VM has no real power draw, so power is estimated from
# resource activity (guide section 5.2):
#     P(t) = P_idle + a*cpu + b*io_ops + c*net_bytes + d*mem_activity
#     E_window = sum P(t) * dt
# cpu is the CPU utilisation of the emulator process (1.0 = one host core fully
# busy), io_ops / net_bytes / mem_activity are per-second rates. The coefficients
# are approximate figures for a small router SoC, not measurements.
P_IDLE = 1.0        # W, device idle
A_CPU = 2.0         # W per fully busy core
B_IO = 0.0005       # W per I/O operation per second
C_NET = 1e-6        # W per network byte per second
D_MEM = 1e-4        # W per page fault per second


def power(cpu_util, io_ops_s, net_bytes_s, mem_faults_s):
    return P_IDLE + A_CPU * cpu_util + B_IO * io_ops_s + C_NET * net_bytes_s + D_MEM * mem_faults_s


def collect_energy(samples, window_dur, net_bytes, sys_count):
    """samples: list of {"dt", "cpu_s", "io_ops", "net_bytes", "mem_faults"} taken about
    once a second by the energy sampler. With no samples (offline pcap build) the
    model falls back to the network term only."""
    if not samples:
        if window_dur <= 0:
            return {k: 0.0 for k in ENERGY_FEATURES}
        samples = [{"dt": window_dur, "cpu_s": 0.0, "io_ops": 0.0,
                    "net_bytes": float(net_bytes), "mem_faults": 0.0}]
    powers, energy, cpu, io, dur = [], 0.0, 0.0, 0.0, 0.0
    for s in samples:
        dt = max(1e-6, float(s["dt"]))
        p = power(s["cpu_s"] / dt, s["io_ops"] / dt, s["net_bytes"] / dt, s["mem_faults"] / dt)
        powers.append(p)
        energy += p * dt
        cpu += s["cpu_s"]; io += s["io_ops"]; dur += dt
    return {
        "energy_mean_power": energy / dur,
        "energy_peak_power": max(powers),
        "energy_j": energy,
        "energy_cpu_util": cpu / dur,
        "energy_io_ops": io,
        "energy_per_syscall": energy / max(1.0, float(sys_count)),
    }


# ================================= all ======================================
def collect_all(pkts, window_dur, syscalls=None, energy_samples=None):
    """Run all collectors and return one flat raw-feature dict."""
    out = {}
    out.update(collect_statistical(pkts, window_dur))
    out.update(collect_protocol(pkts))
    out.update(collect_service(pkts))
    out.update(collect_syscall(syscalls or [], window_dur))
    out.update(collect_energy(energy_samples or [], window_dur, out["byte_count"], out["sys_count"]))
    return {k: float(out.get(k, 0.0)) for k in FEATURE_ORDER}
