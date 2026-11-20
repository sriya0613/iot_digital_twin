#!/usr/bin/env python3 -I
"""test_collection_kit.py — runs the real collect_session.sh / kit.py with STUB system commands.

No twin, no namespaces, no packets: sudo, ip, ping, pgrep, curl, nmap, hping3 and sleep are
replaced by stubs in a temporary PATH. The real stream/label_run.py writes a temporary manifest.

  python3 -I -m pytest tests/test_collection_kit.py -v
"""
import json
import os
import stat
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import kit  # noqa: E402

STUBS = {
    # sudo: drop 'ip netns exec <ns>' and run the rest, so commands run locally against stubs
    "sudo": 'case "$1" in -v|-n) exit 0;; esac; if [ "$1" = ip ] && [ "$2" = netns ] && [ "$3" = exec ]; then shift 4; fi; exec "$@"',
    "ip": 'case "$*" in "netns list") printf "atk\\ncli\\n";; route*|*"route show"*) : ;; esac; exit 0',
    # ping fails the first STUB_PING_FAILS calls (counted in a file), then answers
    "ping": 'n=$(cat "$STUB_LOG.ping" 2>/dev/null || echo 0); echo $((n+1)) > "$STUB_LOG.ping"; '
            '[ "$n" -ge "${STUB_PING_FAILS:-0}" ]',
    "pgrep": 'case "$*" in *watchdog*) [ -n "${STUB_WATCHDOG:-}" ] && echo "77 python3 /x/network/watchdog.py $STUB_WATCHDOG";; '
             '*) echo "4242 sudo python3 run.py record --iface ${STUB_IFACE:-twin-mon} --window 5";; esac; exit 0',
    "curl": 'echo "curl $*" >> "$STUB_LOG"; case "$*" in *http_code*) printf 200;; esac; exit 0',
    "nmap": 'echo "nmap $*" >> "$STUB_LOG"; exit 0',
    "hping3": 'echo "hping3 $*" >> "$STUB_LOG"; exit 0',
    "sleep": "exit 0",
}


@pytest.fixture
def env(tmp_path):
    b = tmp_path / "bin"; b.mkdir()
    for name, body in STUBS.items():
        f = b / name
        f.write_text("#!/usr/bin/env bash\n" + body + "\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    e = dict(os.environ)
    e.update(PATH="%s:%s" % (b, e["PATH"]), MANIFEST=str(tmp_path / "manifest.jsonl"),
             STUB_LOG=str(tmp_path / "calls.log"), SESSION_ID="S07", SESSION_TAG="test",
             BENIGN_BURST_SECONDS="1", BEACON_LONG_SECONDS="1",
             BEACON_LOG=str(tmp_path / "beacon_requests.jsonl"),   # never write into the repo's data/
             KIT_SESSIONS_DIR=str(tmp_path / "sessions"), IDLE_SECONDS="0.1", HEAL_PAD="0", HEAL_CMD="true",
             PREFLIGHT_LOG=str(tmp_path / "preflight_waits.jsonl"))
    return e, tmp_path


def test_full_protocol_writes_session_file_and_all_episodes(env):
    e, tmp = env
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "run_protocol.sh")], env=e,
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr[-2000:]
    sess = json.load(open(tmp / "sessions" / "S07.json"))
    assert sess["status"] == "complete" and sess["stop_epoch"] > sess["start_epoch"]
    assert sorted(sess["episode_order"]) == sorted(["scan", "scan-slow", "bruteforce", "dos", "beacon", "beacon-long"])
    m = manifest(tmp)
    attacks = [x["attack_class"] for x in m if x["label"] == "malware"]
    assert sorted(attacks) == sorted(["scan", "scan", "bruteforce", "dos", "beacon", "beacon"])
    assert [x["label"] for x in m][-1] == "healing"
    assert sum(1 for x in m if x["label"] == "benign") == 4 + 6       # 4 opening + 1 after each attack
    for x in m:                                                       # every run inside the session span
        assert sess["start_epoch"] <= x["start_epoch"] <= x["stop_epoch"] <= sess["stop_epoch"]


def test_protocol_marks_aborted_session(env):
    e, tmp = env
    e["STUB_IFACE"] = "tap1_0.1"                                       # first episode's preflight fails
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "run_protocol.sh")], env=e,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0
    assert json.load(open(tmp / "sessions" / "S07.json"))["status"] == "aborted"


def run(e, scenario):
    return subprocess.run(["bash", os.path.join(ROOT, "scripts", "collect_session.sh"), scenario],
                          env=e, capture_output=True, text=True, timeout=60)


def manifest(tmp):
    return [json.loads(l) for l in open(tmp / "manifest.jsonl")]


@pytest.mark.parametrize("scenario,label,aclass,cmd", [
    ("benign-http", "benign", "", "curl"), ("benign-ping", "benign", "", None),
    ("benign-burst", "benign", "", "curl"), ("scan", "malware", "scan", "nmap"),
    ("scan-slow", "malware", "scan", "nmap"), ("bruteforce", "malware", "bruteforce", "curl"),
    ("dos", "malware", "dos", "hping3"), ("beacon-long", "malware", "beacon", "curl")])
def test_scenario_writes_correct_label(env, scenario, label, aclass, cmd):
    e, tmp = env
    r = run(e, scenario)
    assert r.returncode == 0, r.stderr
    m = manifest(tmp)[-1]
    assert m["label"] == label and m["attack_class"] == aclass
    assert "S07" in m["note"]
    if cmd:
        assert cmd in open(tmp / "calls.log").read()


def test_preflight_rejects_wrong_capture_interface(env):
    e, tmp = env
    e["STUB_IFACE"] = "tap1_0.1"
    r = run(e, "benign-http")
    assert r.returncode != 0
    assert "must be 'twin-mon'" in r.stderr
    assert not (tmp / "manifest.jsonl").exists()      # nothing labelled


def test_beacon_long_uses_session_period_and_logs_valid_json(env):
    e, tmp = env
    r = run(e, "beacon-long")
    assert r.returncode == 0, r.stderr
    assert "period=10s" in manifest(tmp)[-1]["note"]          # S07 -> 10 s
    lines = open(e["BEACON_LOG"]).read().splitlines()
    assert lines, "no beacon request logged"
    for line in lines:
        d = json.loads(line)
        assert d["session"] == "S07" and d["period_s"] == 10


def test_tests_do_not_write_repo_data(env):
    e, tmp = env
    for s in ("beacon-long", "benign-http"):
        assert run(e, s).returncode == 0
    assert not os.path.exists(os.path.join(ROOT, "data", "beacon_requests.jsonl"))


def test_preflight_waits_for_twin_and_logs_wait(env):
    e, tmp = env
    e["STUB_PING_FAILS"] = "2"                                  # twin silent for two checks (as after a DoS)
    r = run(e, "benign-http")
    assert r.returncode == 0, r.stderr
    assert "twin ready after" in r.stdout
    w = [json.loads(l) for l in open(tmp / "preflight_waits.jsonl")]
    assert w[-1]["session"] == "S07" and w[-1]["before"] == "benign-http" and w[-1]["waited_s"] >= 0


def test_preflight_gives_up_after_twin_wait(env):
    e, tmp = env
    e.update(STUB_PING_FAILS="1000", TWIN_WAIT="0")
    r = run(e, "benign-http")
    assert r.returncode != 0 and "not answering ping + HTTP" in r.stderr
    assert not (tmp / "manifest.jsonl").exists()


def test_preflight_refuses_self_healing_watchdog(env):
    e, tmp = env
    e["STUB_WATCHDOG"] = " "                                    # plain watchdog.py: heals
    r = run(e, "benign-http")
    assert r.returncode != 0 and "self-healing watchdog" in r.stderr
    e["STUB_WATCHDOG"] = "--no-heal"                            # report-only watchdog is fine
    assert run(e, "benign-http").returncode == 0


def test_pilot_session_id_runs(env):
    e, tmp = env
    e["SESSION_ID"] = "P01"
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "run_protocol.sh")], env=e,
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr[-1500:]
    assert json.load(open(tmp / "sessions" / "P01.json"))["status"] == "complete"


def test_build_dataset_relative_paths_and_filtering(tmp_path):
    """Real stream/run.py build. Relative raw paths, an empty file and an Oct 3 (tap1_0.1) file:
    only the twin-mon file is built (pilot S00 bugs)."""
    pytest.importorskip("scapy")
    import shutil
    good = os.path.join(ROOT, "data", "raw", "session_20261019T175725.jsonl")      # twin-mon, 1 window
    oct3 = os.path.join(ROOT, "data", "raw", "session_20261003T103513.jsonl")      # tap1_0.1
    if not (os.path.exists(good) and os.path.exists(oct3)):
        pytest.skip("raw files not present")
    shutil.copy(good, tmp_path / "a.jsonl"); shutil.copy(oct3, tmp_path / "b.jsonl")
    (tmp_path / "empty.jsonl").write_text("")
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "build_dataset.sh"), "out.jsonl",
                        "a.jsonl", "b.jsonl", "empty.jsonl"], cwd=str(tmp_path), capture_output=True, text=True, timeout=120)
    assert "[build] 1 raw file(s) captured on twin-mon" in r.stdout, r.stdout + r.stderr
    assert "skipping b.jsonl (captured on 'tap1_0.1'" in r.stderr and "skipping empty.jsonl (empty)" in r.stderr
    assert (tmp_path / "out.jsonl").exists()                   # written where asked, not inside stream/
    assert not os.path.exists(os.path.join(ROOT, "stream", "out.jsonl"))


# ------------------------------------------------------------------ kit.py units
def test_watchdog_healing_parsing():
    assert kit.watchdog_healing(["17579 python3 /h/network/watchdog.py"]) is True
    assert kit.watchdog_healing(["1 python3 network/watchdog.py --no-heal"]) is False
    assert kit.watchdog_healing(["1 python3 network/watchdog.py --status --json"]) is False
    assert kit.watchdog_healing(["1 pgrep -af watchdog.py", "2 bash"]) is False
    assert kit.watchdog_healing([]) is False


def test_raw_files_filter(tmp_path):
    (tmp_path / "e.jsonl").write_text("")
    (tmp_path / "m.jsonl").write_text(json.dumps({"monitors": {"network": "twin-mon"}}) + "\n")
    (tmp_path / "t.jsonl").write_text(json.dumps({"monitors": {"network": "tap1_0.1"}}) + "\n")
    cwd = os.getcwd(); os.chdir(tmp_path)
    try:
        ok, skipped = kit.raw_files(["e.jsonl", "m.jsonl", "t.jsonl", "missing.jsonl"])
    finally:
        os.chdir(cwd)
    assert ok == [str(tmp_path / "m.jsonl")]                    # absolute
    assert [p for p, _ in skipped] == ["e.jsonl", "t.jsonl", "missing.jsonl"]



def test_recorder_iface_parsing():
    assert kit.recorder_iface(["1 sudo python3 run.py record --iface twin-mon --window 5"]) == "twin-mon"
    assert kit.recorder_iface(["1 python3 run.py record --window 5"]) == "tap1_0.1"       # run.py default
    assert kit.recorder_iface(["1 python3 run.py stream --iface=twin-mon"]) == "twin-mon"
    assert kit.recorder_iface(["1 vim run.py", "2 bash"]) == ""
    assert kit.recorder_iface(["1 python3 run.py record --iface twin-mon",
                               "2 python3 run.py record --iface tap1_0.1"]) == "MULTIPLE"


def test_session_start_stop_and_no_reuse(tmp_path):
    r = kit.session_start("S03", tag="t", order=["scan", "dos"], sessions_dir=str(tmp_path), now=100.0, collect_env=False)
    assert r["status"] == "running" and r["start_epoch"] == 100.0 and r["beacon_long_period_s"] == 60   # S03 -> (3-1) % 3 = 2 -> 60 s
    with pytest.raises(FileExistsError):
        kit.session_start("S03", sessions_dir=str(tmp_path), collect_env=False)
    s = kit.session_stop("S03", "complete", sessions_dir=str(tmp_path), now=200.0, collect_env=False)
    assert s["stop_epoch"] == 200.0 and s["status"] == "complete"
    with pytest.raises(RuntimeError):
        kit.session_stop("S03", sessions_dir=str(tmp_path), collect_env=False)


def test_session_id_format_enforced(tmp_path):
    kit.session_start("P01", sessions_dir=str(tmp_path), collect_env=False)      # pilots are allowed
    for bad in ("S1", "s01", "S001", "X01", "P1", ""):
        with pytest.raises(ValueError):
            kit.session_start(bad, sessions_dir=str(tmp_path), collect_env=False)


def test_beacon_periods_rotate_evenly():
    periods = [kit.beacon_period("S%02d" % i) for i in range(1, 16)]
    assert {p: periods.count(p) for p in set(periods)} == {10: 5, 30: 5, 60: 5}


def test_scripts_parse():
    for s in ("collect_session.sh", "run_protocol.sh", "build_dataset.sh", "check_env.sh"):
        subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", s)], check=True)
