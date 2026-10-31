"""twin_view.py - "is the Digital Twin running?" visual for the dashboard.

A second page (persond/pages/2_Twin_View.py renders it). It does NOT change dashboard.py.
It answers, at a glance: is the twin up, is it under attack / contained / healing, and what
is the SDN fabric doing. Two sources:

  TWIN_SOURCE=live    (default) - check the real twin on this host:
                        emulator process, ping 192.168.0.1, its web page, OVS bridge, Ryu flows,
                        plus network/.state/health.json (watchdog) and the latest risk in threat.db
  TWIN_SOURCE=replay  - play back a recording from samples/ (or TWIN_REPLAY=<file>), one window
                        per refresh, so the view animates with no twin running (demo safety net)

The state logic (derive_state, replay_frame) is pure and separately tested in
tests/test_twin_view.py, so it runs inside run_all_tests.py without a browser or a twin.
"""
import json
import os
import subprocess
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEVICE_IP = os.environ.get("DEV_IP", "192.168.0.1")
DEVICE_MAC = os.environ.get("TWIN_MAC", "00:de:fa:1a:01:00")
HOST_IP = os.environ.get("HOST_IP", "192.168.0.2")
RYU_URL = os.environ.get("RYU_REST", "http://127.0.0.1:8080").rstrip("/")
HEALTH_FILE = os.path.join(ROOT, "network", ".state", "health.json")
DB_PATH = os.environ.get("THREAT_DB", os.path.join(os.getcwd(), "threat.db"))
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # Ryu is local

# How the twin's state maps to a colour + headline. Pure, so tests can assert it.
STATE_STYLE = {
    "up":        ("Twin running", "green", "device is up and reachable"),
    "contained": ("Twin quarantined", "red", "traffic is being dropped by the SDN controller"),
    "rate_limited": ("Twin rate-limited", "amber", "device traffic is throttled"),
    "healing":   ("Twin restoring", "amber", "rolling back to the clean baseline"),
    "down":      ("Twin down", "red", "not reachable"),
    "held":      ("Held for a human", "red", "auto-healing stopped after repeated infections"),
    "unknown":   ("No data", "grey", "nothing is feeding the view"),
}


# ---------------------------------------------------------------- pure logic (tested)
def derive_state(checks, risk=None, contained=False, rate_limited=False, held=False, healing=False):
    """checks: {emulator,ping,http,on_bridge,controller} bools (http/on_bridge/controller may be None).
    Returns a state key from STATE_STYLE. Pure - no I/O."""
    alive = bool(checks.get("emulator")) and bool(checks.get("ping"))
    if held:
        return "held"
    if healing:
        return "healing"                 # a reset is in progress (device may be briefly unreachable)
    if not alive:
        return "down"
    if contained:
        return "contained"
    if rate_limited:
        return "rate_limited"
    if risk is not None and risk > 70:
        return "healing"      # high risk but still reachable -> a reset is imminent / in progress
    return "up"


def replay_frame(records, i):
    """Synthesise (checks, risk, contained, rate_limited) from recording window i.
    The twin is 'up' except where a heal record says it was resetting. Pure."""
    windows = [r for r in records if r.get("type") == "window"]
    if not windows:
        return {"emulator": True, "ping": True, "http": True, "on_bridge": True, "controller": True}, None, False, False, False
    r = windows[i % len(windows)]
    risk = r.get("risk_score", 0)
    healing = r.get("detector_action", "") == "restore_started"
    checks = {"emulator": True, "ping": not healing, "http": not healing, "on_bridge": True, "controller": True}
    contained = (risk > 70) and not healing
    rate_limited = 30 <= risk <= 70
    return checks, risk, contained, rate_limited, healing


# ---------------------------------------------------------------- live probes (host)
def _run(cmd, timeout=3):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, "", "")


def _ryu(path):
    try:
        with _OPENER.open(urllib.request.Request(RYU_URL + path), timeout=3) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def live_checks():
    checks = {
        "emulator": _run("pgrep -f qemu-system").returncode == 0,
        "ping": _run("ping -c 1 -W 1 %s" % DEVICE_IP).returncode == 0,
    }
    code = _run("curl -s -o /dev/null -m 2 -w '%%{http_code}' http://%s/" % DEVICE_IP).stdout.strip()
    checks["http"] = code not in ("", "000")
    sw = _ryu("/stats/switches")
    checks["controller"] = bool(sw)
    flows = []
    if sw:
        f = _ryu("/stats/flow/%d" % sw[0])
        flows = (f or {}).get(str(sw[0]), []) if f else []
    checks["on_bridge"] = checks["ping"]      # on the bridge if it answers through it
    return checks, flows


def flows_summary(flows):
    """Containment rules among the switch flows (cookies 0xD00000xx from Person D)."""
    out = {"drop": 0, "allow": 0, "meter": 0, "rules": []}
    for fl in flows or []:
        ck = int(fl.get("cookie", 0))
        if ck not in (0xD0000001, 0xD0000002):
            continue
        acts = fl.get("actions", [])
        kind = "meter" if any("METER" in str(a) for a in acts) else ("drop" if not acts else "allow")
        out[kind] = out.get(kind, 0) + 1
        out["rules"].append({"priority": fl.get("priority"), "match": fl.get("match"), "actions": acts})
    return out


def read_health():
    try:
        h = json.load(open(HEALTH_FILE))
        if time.time() - h.get("updated_epoch", 0) < 30:
            return h
    except Exception:
        pass
    return None


def latest_risk(db=DB_PATH):
    try:
        import sqlite3
        con = sqlite3.connect(db, timeout=2)
        row = con.execute("SELECT risk_score FROM alerts ORDER BY window_start_epoch DESC LIMIT 1").fetchone()
        spark = [r[0] for r in con.execute(
            "SELECT risk_score FROM alerts ORDER BY window_start_epoch DESC LIMIT 40").fetchall()][::-1]
        con.close()
        return (row[0] if row else None), spark
    except Exception:
        return None, []


def device_held(db=DB_PATH):
    try:
        import sqlite3
        con = sqlite3.connect(db, timeout=2)
        n = con.execute("SELECT COUNT(*) FROM device_state WHERE status='held' AND device_ip=?",
                        (DEVICE_IP,)).fetchone()[0]
        con.close()
        return n > 0
    except Exception:
        return False


# ---------------------------------------------------------------- the page (streamlit)
def _topology_svg(state, contained, rate_limited, colors):
    """A small topology: attacker / client / host -> OVS switch -> twin, with Ryu above.
    The attacker link turns red when contained; the twin node is coloured by state."""
    tw = colors.get(STATE_STYLE[state][1], "#888")
    atk_link = "#e5484d" if (contained or rate_limited) else "#8b8d98"
    atk_w = 3 if (contained or rate_limited) else 1.5
    def node(x, y, label, fill, text="#fff"):
        return ('<rect x="%d" y="%d" width="120" height="44" rx="8" fill="%s"/>'
                '<text x="%d" y="%d" fill="%s" font-size="13" font-family="IBM Plex Sans,sans-serif" '
                'text-anchor="middle">%s</text>' % (x, y, fill, x + 60, y + 27, text, label))
    def line(x1, y1, x2, y2, col, w=1.5, dash=""):
        return '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="%s" %s/>' % (
            x1, y1, x2, y2, col, w, ('stroke-dasharray="5 4"' if dash else ""))
    S = []
    # links
    S.append(line(210, 70, 330, 160, atk_link, atk_w))        # attacker -> switch
    S.append(line(210, 160, 330, 180, "#8b8d98"))             # client -> switch
    S.append(line(210, 250, 330, 200, "#8b8d98"))             # host -> switch
    S.append(line(450, 180, 560, 180, tw, 3))                 # switch -> twin
    S.append(line(390, 150, 390, 90, "#6e56cf", 1.5, "dash")) # switch -> ryu
    # nodes
    S.append(node(90, 48, "Attacker", "#e5484d"))
    S.append(node(90, 138, "Client", "#30a46c"))
    S.append(node(90, 228, "Host", "#5b5bd6"))
    S.append(node(330, 158, "OVS switch", "#333"))
    S.append(node(330, 68, "Ryu (SDN)", "#6e56cf"))
    S.append(node(560, 158, "Digital Twin", tw))
    badge = ""
    if contained:
        badge = '<text x="270" y="120" fill="#e5484d" font-size="12" text-anchor="middle">DROP</text>'
    elif rate_limited:
        badge = '<text x="270" y="120" fill="#f5a524" font-size="12" text-anchor="middle">LIMIT</text>'
    return ('<svg viewBox="0 0 700 290" width="100%%" style="max-width:700px">%s%s</svg>'
            % ("".join(S), badge))


def render():
    import streamlit as st
    try:
        from streamlit_autorefresh import st_autorefresh  # optional
        st_autorefresh(interval=2000, key="twinrefresh")
    except Exception:
        pass

    source = os.environ.get("TWIN_SOURCE", "live").lower()
    colors = {"green": "#30a46c", "red": "#e5484d", "amber": "#f5a524", "grey": "#8b8d98"}

    st.markdown("## Digital Twin — live view")
    st.caption("Source: **%s**  ·  device %s" % (source, DEVICE_IP))

    if source == "replay":
        path = os.environ.get("TWIN_REPLAY", os.path.join(ROOT, "samples", "alerts_three_monitor_clean_run.jsonl"))
        try:
            records = [json.loads(l) for l in open(path) if l.strip()]
        except Exception as e:
            st.error("replay file not found: %s (%s)" % (path, e)); return
        i = st.session_state.get("twin_i", 0)
        st.session_state["twin_i"] = i + 1
        checks, risk, contained, rate_limited, healing = replay_frame(records, i)
        flows_s = {"drop": 2 if contained else 0, "allow": 3 if contained else 0,
                   "meter": 1 if rate_limited else 0, "rules": []}
        held = False
        spark = [replay_frame(records, j)[1] or 0 for j in range(max(0, i - 39), i + 1)]
        health = None
    else:
        checks, flows = live_checks()
        flows_s = flows_summary(flows)
        contained = flows_s["drop"] > 0
        rate_limited = flows_s["meter"] > 0
        risk, spark = latest_risk()
        held = device_held()
        health = read_health()
        healing = bool(health and (health.get("state") in ("healing", "settling")))

    state = derive_state(checks, risk, contained, rate_limited, held, healing)
    text, tone, detail = STATE_STYLE[state]

    # headline pill
    st.markdown(
        '<div style="display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1rem;border-radius:999px;'
        'background:%s22;color:%s;font-weight:600;font-size:1.1rem">'
        '<span style="width:.7rem;height:.7rem;border-radius:50%%;background:%s"></span>%s</div>'
        '<span style="margin-left:.75rem;color:#8b8d98">%s</span>'
        % (colors[tone], colors[tone], colors[tone], text, detail), unsafe_allow_html=True)

    st.markdown(_topology_svg(state, contained, rate_limited, colors), unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Router check**")
        for k, lbl in [("emulator", "Emulator process"), ("ping", "Ping 192.168.0.1"),
                       ("http", "Web page"), ("controller", "Ryu controller")]:
            v = checks.get(k)
            dot = "🟢" if v else ("⚪" if v is None else "🔴")
            st.write("%s %s" % (dot, lbl))
    with c2:
        st.markdown("**SDN containment**")
        st.write("Drop rules: **%d**" % flows_s["drop"])
        st.write("Allow rules: **%d**" % flows_s["allow"])
        st.write("Rate-limit meter: **%d**" % flows_s["meter"])
        st.write("Attacker: **%s**" % ("BLOCKED" if contained else "allowed"))
    with c3:
        st.markdown("**Latest risk**")
        st.metric("risk score", risk if risk is not None else "–")
        if spark:
            try:
                import pandas as pd
                st.line_chart(pd.DataFrame({"risk": spark}), height=120)
            except Exception:
                pass

    if health:
        st.caption("watchdog: state **%s**, last event **%s**"
                   % (health.get("state"), (health.get("last_event") or {}).get("event", "-")))
    st.caption("Open the router: http://%s/" % DEVICE_IP)
