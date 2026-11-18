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
    "sudo": 'if [ "$1" = ip ] && [ "$2" = netns ] && [ "$3" = exec ]; then shift 4; fi; exec "$@"',
    "ip": 'case "$*" in "netns list") printf "atk\\ncli\\n";; route*|*"route show"*) : ;; esac; exit 0',
    "ping": "exit 0",
    "pgrep": 'echo "4242 sudo python3 run.py record --iface ${STUB_IFACE:-twin-mon} --window 5"',
    "curl": 'echo "curl $*" >> "$STUB_LOG"; exit 0',
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
             KIT_SESSIONS_DIR=str(tmp_path / "sessions"), IDLE_SECONDS="0.1", HEAL_PAD="0", HEAL_CMD="true")
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


# ------------------------------------------------------------------ kit.py units
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
    for bad in ("S1", "s01", "S001", "X01", ""):
        with pytest.raises(ValueError):
            kit.session_start(bad, sessions_dir=str(tmp_path), collect_env=False)


def test_beacon_periods_rotate_evenly():
    periods = [kit.beacon_period("S%02d" % i) for i in range(1, 16)]
    assert {p: periods.count(p) for p in set(periods)} == {10: 5, 30: 5, 60: 5}


def test_scripts_parse():
    for s in ("collect_session.sh", "run_protocol.sh", "build_dataset.sh", "check_env.sh"):
        subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", s)], check=True)
