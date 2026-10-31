"""
monitors.py — the two live monitors that are not the packet sniffer.

  SyscallTail    follows a text log of the guest's system calls and turns each
                 line into an event {"ts", "pid", "syscall"}.
  EnergySampler  samples the emulator process once a second (CPU time, I/O
                 operations, page faults) plus the network bytes seen by the
                 sniffer, and hands the samples to the virtual energy model.

Both run in background threads and push into the WindowAggregator.
"""
import os
import re
import threading
import time

# -- syscall log formats -------------------------------------------------------
# 1. Firmadyne/FirmAE instrumented kernel, written to the QEMU serial log:
#       [  123.456789] firmadyne: inet_bind[PID: 1289 (httpd)]: proto:SOCK_STREAM, port:80
# 2. strace (with or without -f / -t / -tt / -ttt):
#       [pid  1289] 12:00:01.123456 open("/etc/passwd", O_RDONLY) = 3
#       1289  1730000000.123456 socket(AF_INET, SOCK_STREAM, 0) = 4
RE_FIRMADYNE = re.compile(r"firmadyne: ([A-Za-z_][A-Za-z0-9_]*)\[PID: (\d+)")
RE_STRACE = re.compile(
    r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?"                    # optional pid
    r"(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+|\d{9,}(?:\.\d+)?\s+)?"   # optional timestamp
    r"([a-z_][a-z0-9_]*)\(")
_PREFIXES = ("__sys_", "sys_", "do_", "inet_", "vfs_", "__")
# kernel-hook names the Firmadyne/FirmAE kernel prints -> the system call they stand for
_ALIASES = {"mmap_region": "mmap", "send_sig_info": "kill", "fork_ret": None,
            "register_vlan_dev": "netconfig", "inet_insert_ifa": "netconfig", "br_add_if": "netconfig"}


def normalise(name):
    """sys_socket / do_execve / inet_bind / do_sys_open -> socket / execve / bind / open.
    Returns None for a line that should not be counted (e.g. a return-value line)."""
    name = name.lower()
    changed = True
    while changed:
        changed = False
        for p in _PREFIXES:
            if name.startswith(p) and len(name) > len(p):
                name, changed = name[len(p):], True
                break
    return _ALIASES.get(name, name)


def parse_syscall_line(line):
    """Return (pid, syscall) or None."""
    m = RE_FIRMADYNE.search(line)
    if m:
        name = normalise(m.group(1))
        return (int(m.group(2)), name) if name else None
    m = RE_STRACE.match(line.strip())
    if m:
        name = normalise(m.group(3))
        return (int(m.group(1) or m.group(2) or 0), name) if name else None
    return None


class SyscallTail(threading.Thread):
    """tail -F a syscall log. Each parsed line becomes an event stamped with the
    time it was read, which is what places it in a 5-second window."""

    def __init__(self, path, on_event, from_start=False, poll=0.2):
        super().__init__(daemon=True)
        self.path, self.on_event, self.from_start, self.poll = path, on_event, from_start, poll
        self.n_events = self.n_lines = 0
        self._halt = threading.Event()

    def stop(self):
        self._halt.set()

    def run(self):
        f, inode, pos = None, None, 0
        first = True
        while not self._halt.is_set():
            try:
                st = os.stat(self.path)
            except OSError:
                f = None
                time.sleep(self.poll)
                continue
            if f is None or st.st_ino != inode or st.st_size < pos:    # new, replaced or truncated
                try:
                    f = open(self.path, "rb")
                except OSError:
                    time.sleep(self.poll)
                    continue
                inode = st.st_ino
                if first and not self.from_start:
                    f.seek(0, os.SEEK_END)                             # only what happens from now on
                first = False
            got = False
            while True:
                here = f.tell()
                raw = f.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):                           # partial line, wait for the rest
                    f.seek(here)
                    break
                got = True
                self.n_lines += 1
                ev = parse_syscall_line(raw.decode(errors="replace"))
                if ev:
                    self.n_events += 1
                    self.on_event({"ts": time.time(), "pid": ev[0], "syscall": ev[1]})
            pos = f.tell()
            if not got:
                time.sleep(self.poll)


# -- energy sampler ----------------------------------------------------------------
def find_emulator_pid(pattern="qemu-system"):
    """PID of the running emulator (the largest matching process), or None."""
    best, best_rss = None, -1
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % d, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
            if pattern not in cmd or "run.py" in cmd:
                continue
            with open("/proc/%s/statm" % d) as f:
                rss = int(f.read().split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if rss > best_rss:
            best, best_rss = int(d), rss
    return best


def read_proc(pid):
    """(cpu_seconds, page_faults, io_ops) so far for a process, or None if it is gone."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            rest = f.read().rsplit(")", 1)[1].split()
        # rest[0] is field 3 (state); minflt=10, majflt=12, utime=14, stime=15
        minflt, majflt, utime, stime = int(rest[7]), int(rest[9]), int(rest[11]), int(rest[12])
    except (OSError, IndexError, ValueError):
        return None
    io = 0
    try:
        with open("/proc/%d/io" % pid) as f:
            for line in f:
                if line.startswith(("syscr:", "syscw:")):
                    io += int(line.split()[1])
    except (OSError, ValueError):
        pass                                   # needs root; energy then omits the I/O term
    return (utime + stime) / float(os.sysconf("SC_CLK_TCK")), minflt + majflt, io


class EnergySampler(threading.Thread):
    """Once per interval: how much CPU, I/O and memory activity the emulator
    process had, and how many network bytes the sniffer saw."""

    def __init__(self, on_sample, pid="auto", pattern="qemu-system", interval=1.0):
        super().__init__(daemon=True)
        self.on_sample, self.pid_arg, self.pattern, self.interval = on_sample, pid, pattern, interval
        self.pid = None
        self.n_samples = self.n_with_pid = 0
        self._net = 0
        self._lock = threading.Lock()
        self._halt = threading.Event()

    def stop(self):
        self._halt.set()

    def add_net(self, nbytes):
        with self._lock:
            self._net += nbytes

    def _resolve(self):
        if self.pid_arg == "auto":
            return find_emulator_pid(self.pattern)
        return int(self.pid_arg)

    def run(self):
        prev, t_prev = None, time.time()
        while not self._halt.wait(self.interval):
            now = time.time()
            dt = now - t_prev
            t_prev = now
            with self._lock:
                net, self._net = self._net, 0
            cur = read_proc(self.pid) if self.pid else None
            if cur is None:                    # emulator not found or restarted: look again
                self.pid = self._resolve()
                cur = read_proc(self.pid) if self.pid else None
                prev = None
            s = {"ts": now, "dt": dt, "cpu_s": 0.0, "io_ops": 0.0, "net_bytes": float(net), "mem_faults": 0.0}
            if cur is not None and prev is not None:
                s["cpu_s"] = max(0.0, cur[0] - prev[0])
                s["mem_faults"] = float(max(0, cur[1] - prev[1]))
                s["io_ops"] = float(max(0, cur[2] - prev[2]))
                self.n_with_pid += 1
            prev = cur
            self.n_samples += 1
            self.on_sample(s)
