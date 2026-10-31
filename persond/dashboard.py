#!/usr/bin/env python3
"""dashboard.py - live monitoring screen for Person D's policy & self-healing engine.

Reads threat.db (written by run_pipeline.py / healing_engine.py) and refreshes every 2 seconds.

  pip install streamlit
  streamlit run persond/dashboard.py            (run from the personD_handoff folder)

Another database:   Windows:  set THREAT_DB=other.db      Linux/Mac:  THREAT_DB=other.db streamlit run ...

Top to bottom:
  1. header with device, firmware and a status pill (Healthy / Rate-limited / Healing / Cooling down / Held for human)
  2. four stat cards: current risk, alerts processed, heals done, escalations
  3. risk timeline with the observe / rate-limit / quarantine bands shaded and heals marked
  4. "Why": top 3 explanation (SHAP) features of the latest alert, in plain English
  5. held devices with a Clear button (same as: python persond/healing_engine.py --clear <ip>)
  6. heal history
  7. recent actions (latest 20 alerts)

Colour carries meaning only: green = healthy / verified, amber = rate-limit / pending,
red = quarantine / held / reinfected, grey = everything else. Every colour comes with a text label.
"""
import html
import json
import os
import sqlite3
import time
import sys
from datetime import datetime, timezone

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy import OBSERVE_BELOW, QUARANTINE_ABOVE  # noqa: E402
from threat_db import ThreatDatabase  # noqa: E402

DB_PATH = os.environ.get("THREAT_DB", "threat.db")
REFRESH_SECONDS = 2
RUN_GAP = 600              # alerts more than 10 min apart belong to different runs (the recordings are days apart)

# ---- plain-English names for the detector's features (common.py) --------------------------------
FEATURE_NAMES = {
    "pkt_count": "Packets in the window", "byte_count": "Bytes in the window",
    "mean_pkt_size": "Average packet size", "std_pkt_size": "Spread of packet sizes",
    "mean_iat": "Average gap between packets", "std_iat": "Spread of gaps between packets",
    "pkts_per_sec": "Packets per second", "bytes_per_sec": "Bytes per second",
    "frac_tcp": "Share of TCP traffic", "frac_udp": "Share of UDP traffic", "frac_icmp": "Share of ping (ICMP) traffic",
    "frac_arp": "Share of ARP traffic", "frac_other": "Share of other traffic",
    "n_unique_src_ports": "Distinct source ports", "n_unique_dst_ports": "Distinct ports contacted",
    "frac_syn": "Share of connection attempts (SYN)", "frac_ack": "Share of acknowledgements (ACK)",
    "frac_rst": "Share of refused connections (RST)", "mean_ttl": "Average packet lifetime (TTL)",
    "n_dns_mdns": "Name lookups (DNS / mDNS)", "n_dhcp": "Address requests (DHCP)",
    "n_arp_req": "ARP requests", "n_arp_reply": "ARP replies", "n_http": "Web requests (HTTP)",
    "n_https": "Secure web requests (HTTPS)", "n_broadcast": "Broadcast packets", "n_multicast": "Multicast packets",
    "distinct_l4_services": "Distinct services used",
    "sys_count": "System calls", "sys_per_sec": "System calls per second", "sys_unique": "Distinct system calls",
    "sys_rare_count": "Rare system calls", "sys_entropy": "Variety of system calls",
    "sys_frac_net": "Share of network system calls", "sys_frac_file": "Share of file system calls",
    "sys_frac_proc": "Share of process system calls", "sys_n_exec": "Programs started (execve)",
    "sys_ngram_unique": "Distinct system-call sequences", "sys_n_pids": "Processes seen",
    "energy_mean_power": "Average power (modelled)", "energy_peak_power": "Peak power (modelled)",
    "energy_j": "Energy used (modelled)", "energy_cpu_util": "CPU use", "energy_io_ops": "Disk / IO operations",
    "energy_per_syscall": "Energy per system call",
}

# ---- colour tokens, one set per theme ----------------------------------------------------------
THEMES = {
    "light": dict(surface="#ffffff", sunken="#f4f6f8", border="#dde2e8", ink="#1b2430", muted="#5f6b7a",
                  faint="#9aa4b1", line="#41536a", green="#16834a", green_bg="#e6f4ec", amber="#a86a08",
                  amber_bg="#fbf1dc", red="#c2373a", red_bg="#fbe7e7", grey_bg="#eef1f4", band=0.85),
    "dark": dict(surface="#151a21", sunken="#0f1318", border="#2a323d", ink="#e5e9ef", muted="#9aa5b3",
                 faint="#667282", line="#b9c4d2", green="#45c17e", green_bg="#14301f", amber="#e5a83b",
                 amber_bg="#352812", red="#f06a6a", red_bg="#3a1a1c", grey_bg="#232a33", band=0.55),
}

# meaning -> colour name; used for pills, chart marks and table badges
TONE = {"observe": "grey", "rate_limit": "amber", "quarantine": "red", "ignored": "grey", "held": "red",
        "verified": "green", "pending": "amber", "unverified": "grey", "reinfected": "red", "failed": "red",
        "ok": "green"}
ACTION_TEXT = {"observe": "Observe", "rate_limit": "Rate-limit", "quarantine": "Quarantine",
               "ignored": "Ignored (healing)", "held": "Held"}

st.set_page_config(page_title="Self-healing dashboard", page_icon="🛡️", layout="wide")


def theme():
    """Current Streamlit theme ('light' or 'dark'). Older Streamlit versions: light."""
    try:
        return "dark" if st.context.theme.type == "dark" else "light"
    except AttributeError:
        return "light"


def css(t):
    """All styling for the HTML parts of the page, built from the theme tokens."""
    return """
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  html, body, [class*="st-"], .pd {{ font-family: 'IBM Plex Sans', system-ui, sans-serif; }}
  .block-container {{ padding-top: 3.5rem; max-width: 1280px; }}
  .pd {{ color: {ink}; font-variant-numeric: tabular-nums; }}
  .pd-head {{ display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
             padding-bottom: 1rem; border-bottom: 1px solid {border}; margin-bottom: 1.25rem; }}
  .pd-title {{ font-size: 1.45rem; font-weight: 600; letter-spacing: -0.01em; margin: 0; }}
  .pd-sub {{ color: {muted}; font-size: 0.92rem; margin-top: 0.15rem; }}
  .pd-pill {{ display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.45rem 0.95rem; border-radius: 999px;
             font-weight: 600; font-size: 0.95rem; }}
  .pd-pill .dot {{ width: 0.6rem; height: 0.6rem; border-radius: 50%; background: currentColor; }}
  .pd-cards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.75rem; margin-bottom: 1.25rem; }}
  @media (max-width: 800px) {{ .pd-cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  .pd-card {{ background: {surface}; border: 1px solid {border}; border-radius: 10px; padding: 0.9rem 1rem; }}
  .pd-card .k {{ color: {muted}; font-size: 0.85rem; }}
  .pd-card .v {{ font-size: 2rem; font-weight: 600; line-height: 1.15; margin: 0.2rem 0; }}
  .pd-card .s {{ color: {muted}; font-size: 0.85rem; }}
  .pd-h {{ font-size: 1.05rem; font-weight: 600; margin: 0.4rem 0 0.6rem; }}
  .pd-note {{ color: {muted}; font-size: 0.85rem; }}
  .pd-badge {{ display: inline-block; padding: 0.1rem 0.55rem; border-radius: 999px; font-size: 0.82rem; font-weight: 500; }}
  .pd-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; background: {surface};
              border: 1px solid {border}; border-radius: 10px; overflow: hidden; }}
  .pd-table th {{ text-align: left; color: {muted}; font-weight: 500; padding: 0.55rem 0.8rem;
                 background: {sunken}; border-bottom: 1px solid {border}; }}
  .pd-table td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid {border}; }}
  .pd-table tr:last-child td {{ border-bottom: none; }}
  .pd-table td.num, .pd-table th.num {{ text-align: right; }}
  .pd-why {{ background: {surface}; border: 1px solid {border}; border-radius: 10px; padding: 0.9rem 1rem; }}
  .pd-bar-row {{ display: grid; grid-template-columns: 1fr 3.5rem; gap: 0.6rem; align-items: center; margin: 0.55rem 0; }}
  .pd-bar-name {{ font-size: 0.92rem; margin-bottom: 0.25rem; }}
  .pd-bar-name span {{ color: {muted}; font-size: 0.8rem; }}
  .pd-track {{ background: {grey_bg}; border-radius: 4px; height: 0.55rem; }}
  .pd-fill {{ height: 100%; border-radius: 4px; }}
  .pd-bar-val {{ text-align: right; font-size: 0.9rem; }}
  .pd-held {{ border: 1px solid {red}; background: {red_bg}; color: {ink}; border-radius: 10px; padding: 0.75rem 1rem; }}
  .pd-empty {{ border: 1px dashed {border}; border-radius: 12px; padding: 2.5rem 2rem; text-align: center; }}
  .pd-empty code {{ background: {sunken}; padding: 0.15rem 0.4rem; border-radius: 4px; }}
</style>""".format(**t)


def badge(text, tone, t):
    """A small coloured label. Grey tone for neutral things."""
    fg = t[tone] if tone != "grey" else t["muted"]
    bg = t[tone + "_bg"]
    return '<span class="pd-badge" style="color:%s;background:%s">%s</span>' % (fg, bg, html.escape(text))


def fmt_time(epoch, seconds=True):
    if epoch is None or pd.isna(epoch):
        return "–"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%d %b %H:%M:%S" if seconds else "%d %b %H:%M")


# ---- data ---------------------------------------------------------------------------------------
def load(path):
    """Read the tables the dashboard needs. Returns None when there is no data yet."""
    if not os.path.exists(path):
        return None
    ThreatDatabase(path).con.close()                 # adds any missing tables / columns (older threat.db)
    con = sqlite3.connect(path, timeout=5)
    q = lambda sql: pd.read_sql_query(sql, con)       # noqa: E731
    d = {"alerts": q("SELECT a.*, x.action, x.reason FROM alerts a LEFT JOIN actions x USING (alert_id) "
                     "ORDER BY a.window_start_epoch"),
         "heals": q("SELECT * FROM heals ORDER BY emitted_at_epoch"),
         "held": q("SELECT * FROM device_state WHERE status = 'held'"),
         "esc": q("SELECT * FROM escalations ORDER BY at_epoch"),
         "health": q("SELECT * FROM health ORDER BY emitted_at_epoch")}
    con.close()
    if d["alerts"].empty:
        return None
    a = d["alerts"]
    a["time"] = pd.to_datetime(a["window_start_epoch"], unit="s")
    a["run"] = (a["window_start_epoch"].diff() > RUN_GAP).cumsum()
    if len(d["heals"]):
        d["heals"]["time"] = pd.to_datetime(d["heals"]["emitted_at_epoch"], unit="s")
    return d


def twin_running(dev, alerts, health):
    """Is the digital twin alive right now? (text, tone, detail).
    Primary signal: 5-second windows are still arriving (detector is scoring live traffic).
    If Person A's watchdog is feeding 'health' records, a recent node_dead/heal overrides it."""
    now = time.time()
    # watchdog health (only present if the watchdog is running)
    if health is not None and len(health):
        try:
            last_h = health.iloc[-1]
            age_h = now - float(last_h["emitted_at_epoch"])
            ev = (json.loads(last_h["raw_json"]) or {}).get("event", "") if last_h.get("raw_json") else ""
            if age_h < 180:
                if ev in ("node_dead", "heal_failed"):
                    return "Twin down", "red", "watchdog: %s %ds ago" % (ev, int(age_h))
                if ev in ("heal_started", "heal_ok"):
                    return "Twin restoring", "amber", "watchdog healing"
        except Exception:
            pass
    # freshness of the alert stream = the twin is producing traffic the detector can see
    mine = alerts[alerts["device_ip"] == dev]
    if len(mine):
        age = now - float(mine["window_end_epoch"].max())
        if age < 15:
            return "Twin live", "green", "windows arriving"
        if age < 60:
            return "Twin quiet", "amber", "last window %ds ago" % int(age)
    return "No live data", "grey", "detector not running?"


def device_status(dev, alerts, heals, held):
    """Status pill: (text, tone). Worked out from the stored decisions, see the notes in the code."""
    if (held["device_ip"] == dev).any():
        return "Held for human", "red"
    mine = alerts[alerts["device_ip"] == dev]
    last = mine.iloc[-1]
    if last["action"] in ("ignored", "quarantine"):
        # healing = no heal has finished since the last quarantine decision; cooling down = one has
        quar = mine[mine["action"] == "quarantine"]
        q_end = quar["window_end_epoch"].max() if len(quar) else None
        h = heals[heals["device_ip"] == dev] if len(heals) else heals
        healed_after = len(h) and q_end is not None and (h["emitted_at_epoch"] >= q_end).any()
        return ("Cooling down", "amber") if healed_after else ("Healing", "red")
    if last["action"] == "rate_limit":
        return "Rate-limited", "amber"
    return "Healthy", "green"


# ---- page parts ---------------------------------------------------------------------------------
def header(dev, firmware, status, twin, t):
    text, tone = status
    tw_text, tw_tone, tw_detail = twin
    tw_col = t[tw_tone] if tw_tone != "grey" else t["muted"]
    tw_bg = t[tw_tone + "_bg"]
    st.markdown(
        '<div class="pd pd-head"><div><p class="pd-title">IoT firmware twin · self-healing</p>'
        '<div class="pd-sub">Device %s%s</div></div>'
        '<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">'
        '<span class="pd-pill" style="color:%s;background:%s" title="%s"><span class="dot"></span>%s</span>'
        '<span class="pd-pill" style="color:%s;background:%s"><span class="dot"></span>%s</span>'
        '</div></div>'
        % (html.escape(dev), (" · " + html.escape(firmware)) if firmware else " · firmware not recorded",
           tw_col, tw_bg, html.escape(tw_detail), tw_text,
           t[tone] if tone != "grey" else t["muted"], t[tone + "_bg"], text),
        unsafe_allow_html=True)


def cards(alerts, heals, esc, held, t):
    last = alerts.iloc[-1]
    n_rate = int((alerts["action"] == "rate_limit").sum())
    n_quar = int((alerts["action"] == "quarantine").sum())
    verified = int((heals["verify_status"] == "verified").sum()) if len(heals) else 0
    risk_tone = "red" if last["risk_score"] > QUARANTINE_ABOVE else "amber" if last["risk_score"] >= OBSERVE_BELOW else "ink"
    card = '<div class="pd-card"><div class="k">%s</div><div class="v" style="color:%s">%s</div><div class="s">%s</div></div>'
    st.markdown('<div class="pd pd-cards">' + "".join([
        card % ("Current risk", t[risk_tone], int(last["risk_score"]), "latest window · %s" % last["threat_label"]),
        card % ("Alerts processed", t["ink"], len(alerts), "%d rate-limited · %d quarantined" % (n_rate, n_quar)),
        card % ("Heals done", t["ink"], len(heals), "%d verified" % verified),
        card % ("Escalations", t["red"] if len(held) else t["ink"], len(esc), "%d held now" % len(held)),
    ]) + "</div>", unsafe_allow_html=True)


def timeline(ra, rh, t):
    """Risk over time: shaded policy bands, one line, coloured dots for non-observe decisions, heal markers."""
    x0, x1 = ra["time"].min(), ra["time"].max()
    bands = pd.DataFrame({"y0": [0, OBSERVE_BELOW, QUARANTINE_ABOVE], "y1": [OBSERVE_BELOW, QUARANTINE_ABOVE, 100],
                          "name": ["observe", "rate-limit", "quarantine"],
                          "fill": [t["grey_bg"], t["amber_bg"], t["red_bg"]], "x0": x0, "x1": x1})
    shade = alt.Chart(bands).mark_rect(opacity=t["band"]).encode(
        x="x0:T", x2="x1:T", y="y0:Q", y2="y1:Q", color=alt.Color("fill:N", scale=None))
    band_text = alt.Chart(bands).mark_text(align="right", dx=-6, dy=10, fontSize=11, color=t["muted"]).encode(
        x="x1:T", y="y1:Q", text="name:N")
    yax = alt.Axis(values=[0, OBSERVE_BELOW, QUARANTINE_ABOVE, 100], labelColor=t["muted"], titleColor=t["muted"],
                   grid=False, domain=False, ticks=False)
    base = alt.Chart(ra).encode(x=alt.X("time:T", title=None, axis=alt.Axis(format="%H:%M:%S", labelColor=t["muted"],
                                                                             grid=False, domainColor=t["border"],
                                                                             tickColor=t["border"])))
    line = base.mark_line(color=t["line"], strokeWidth=2).encode(
        y=alt.Y("risk_score:Q", title="risk score", scale=alt.Scale(domain=[0, 100]), axis=yax))
    ra = ra.assign(decision=ra["action"].map(lambda a: ACTION_TEXT.get(a, a)),
                   tone=ra["action"].map(lambda a: TONE.get(a, "grey")))
    colour = {"red": t["red"], "amber": t["amber"], "green": t["green"], "grey": t["faint"]}
    dots = alt.Chart(ra).mark_circle(size=60, opacity=1, stroke=t["surface"], strokeWidth=1.5).encode(
        x="time:T", y="risk_score:Q",
        color=alt.Color("decision:N", title=None,
                        scale=alt.Scale(domain=list(ACTION_TEXT.values()),
                                        range=[colour[TONE[k]] for k in ACTION_TEXT]),
                        legend=alt.Legend(orient="top", labelColor=t["muted"], symbolType="circle")),
        tooltip=[alt.Tooltip("time:T", title="window", format="%H:%M:%S"), alt.Tooltip("risk_score:Q", title="risk"),
                 alt.Tooltip("threat_label:N", title="label"), alt.Tooltip("decision:N")])
    layers = [shade, band_text, line, dots]
    if len(rh):
        rh = rh.assign(verify=rh["verify_status"], y=100)
        marks = alt.Chart(rh).mark_rule(strokeDash=[3, 3], color=t["muted"]).encode(x="time:T")
        flags = alt.Chart(rh).mark_point(shape="diamond", size=110, filled=True, color=t["green"],
                                         stroke=t["surface"], strokeWidth=1.5).encode(
            x="time:T", y=alt.value(6),
            tooltip=[alt.Tooltip("time:T", title="heal finished", format="%H:%M:%S"),
                     alt.Tooltip("restore_seconds:Q", title="restore seconds"), alt.Tooltip("verify:N")])
        layers += [marks, flags]
    return alt.layer(*layers).properties(height=300).configure_view(stroke=None).configure(background="transparent")


def why_panel(last, t):
    """Top 3 explanation features of the latest alert, as simple bars."""
    exp = json.loads(last["explanation_json"] or "[]")[:3]
    head = '<div class="pd-h">Why — latest alert (risk %d, %s)</div>' % (last["risk_score"], html.escape(last["threat_label"]))
    if not exp:
        st.markdown('<div class="pd">' + head + '<div class="pd-why pd-note">This alert has no explanation.</div></div>',
                    unsafe_allow_html=True)
        return
    biggest = max(abs(e["impact"]) for e in exp) or 1
    rows = []
    for e in exp:
        up = e["impact"] > 0
        rows.append('<div class="pd-bar-row"><div><div class="pd-bar-name">%s <span>%s</span></div>'
                    '<div class="pd-track"><div class="pd-fill" style="width:%d%%;background:%s"></div></div></div>'
                    '<div class="pd-bar-val" style="color:%s">%+.2f</div></div>'
                    % (html.escape(FEATURE_NAMES.get(e["feature"], e["feature"])),
                       "raises risk" if up else "lowers risk",
                       max(4, round(100 * abs(e["impact"]) / biggest)),
                       t["red"] if up else t["faint"], t["red"] if up else t["muted"], e["impact"]))
    st.markdown('<div class="pd">' + head + '<div class="pd-why">' + "".join(rows) +
                '<div class="pd-note" style="margin-top:.5rem">Bar length = how strongly the feature pushed this '
                'verdict (SHAP impact).</div></div></div>', unsafe_allow_html=True)


def held_panel(held, t):
    st.markdown('<div class="pd pd-h">Held devices</div>', unsafe_allow_html=True)
    if held.empty:
        st.markdown('<div class="pd pd-why pd-note">%s No device is held. Auto-healing is on.</div>'
                    % badge("none", "green", t), unsafe_allow_html=True)
        return
    for _, r in held.iterrows():
        st.markdown('<div class="pd pd-held"><b>%s</b> is held for a human: %s (since %s). Auto-reset is stopped '
                    'and the device stays isolated.</div>'
                    % (html.escape(r["device_ip"]), html.escape(r["reason"]), fmt_time(r["since_epoch"])),
                    unsafe_allow_html=True)
        if st.button("Clear %s" % r["device_ip"], key="clear-" + r["device_ip"], type="secondary",
                     help="Releases the device and turns auto-reset back on (same as healing_engine.py --clear)"):
            ThreatDatabase(DB_PATH).clear(r["device_ip"], by="dashboard")
            st.toast("Cleared %s. Auto-reset is on again." % r["device_ip"])
            st.rerun()


def table(headers, rows, numeric=()):
    th = "".join('<th class="%s">%s</th>' % ("num" if i in numeric else "", h) for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join('<td class="%s">%s</td>' % ("num" if i in numeric else "", c)
                                    for i, c in enumerate(r)) + "</tr>" for r in rows)
    return '<table class="pd pd-table"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (th, body)


def heal_history(heals, t):
    st.markdown('<div class="pd pd-h">Heal history</div>', unsafe_allow_html=True)
    if heals.empty:
        st.markdown('<div class="pd pd-why pd-note">No heals yet.</div>', unsafe_allow_html=True)
        return
    rows = []
    for _, h in heals.iloc[::-1].iterrows():
        rows.append([fmt_time(h["emitted_at_epoch"]),
                     "–" if pd.isna(h["trigger_risk"]) else int(h["trigger_risk"]),
                     "%.1f" % h["restore_seconds"],
                     badge("ok", "green", t) if h["ok"] else badge("failed", "red", t),
                     badge(h["verify_status"], TONE.get(h["verify_status"], "grey"), t),
                     "our engine" if h["source"] == "healing_engine" else "detector"])
    st.markdown(table(["Finished (UTC)", "Trigger risk", "Restore s", "Result", "Verify", "By"], rows, numeric=(1, 2)),
                unsafe_allow_html=True)


def recent_actions(alerts, t):
    st.markdown('<div class="pd pd-h">Recent actions <span class="pd-note">latest 20 alerts</span></div>',
                unsafe_allow_html=True)
    rows = []
    for _, a in alerts.tail(20).iloc[::-1].iterrows():
        act = a["action"] or "–"
        rows.append([fmt_time(a["window_start_epoch"]), int(a["risk_score"]), html.escape(a["threat_label"]),
                     badge(ACTION_TEXT.get(act, act), TONE.get(act, "grey"), t),
                     '<span class="pd-note">%s</span>' % html.escape(a["reason"] or "")])
    st.markdown(table(["Window (UTC)", "Risk", "Label", "Action", "Reason"], rows, numeric=(1,)), unsafe_allow_html=True)


def empty_state(t):
    st.markdown(
        '<div class="pd pd-empty"><p class="pd-title">Waiting for alerts</p>'
        '<p class="pd-sub">Nothing is in <code>%s</code> yet. Start the pipeline in another terminal, '
        'for example:</p><p><code>python tools/replay_alerts.py samples/SYNTHETIC_risk_ladder.jsonl --speed 1 | '
        'python persond/run_pipeline.py -</code></p><p class="pd-note">This page checks again every %d seconds.</p></div>'
        % (html.escape(DB_PATH), REFRESH_SECONDS), unsafe_allow_html=True)


# ---- the page: re-drawn in place every 2 s (a fragment re-runs alone, so the scroll position stays) ----
@st.fragment(run_every=REFRESH_SECONDS)
def live():
    t = THEMES[theme()]
    st.markdown(css(t), unsafe_allow_html=True)
    d = load(DB_PATH)
    if d is None:
        empty_state(t)
        return
    alerts, heals, held, esc = d["alerts"], d["heals"], d["held"], d["esc"]
    last = alerts.iloc[-1]
    dev = last["device_ip"]
    fw = alerts["firmware_id"].dropna()
    header(dev, fw.iloc[-1] if len(fw) else None, device_status(dev, alerts, heals, held),
           twin_running(dev, alerts, d.get("health")), t)
    cards(alerts, heals, esc, held, t)

    # timeline of one run (newest by default)
    runs = alerts.groupby("run")["window_start_epoch"].agg(["min", "count"]).reset_index()
    left, right = st.columns([3, 1])
    left.markdown('<div class="pd pd-h">Risk timeline</div>', unsafe_allow_html=True)
    choice = right.selectbox("Run", list(range(len(runs))), index=len(runs) - 1, label_visibility="collapsed",
                             format_func=lambda i: "Run %d · %s · %d alerts" % (i + 1, fmt_time(runs.loc[i, "min"], False),
                                                                               runs.loc[i, "count"]),
                             help="Alerts more than 10 minutes apart are separate runs. The newest is shown first.")
    ra = alerts[alerts["run"] == runs.loc[choice, "run"]]
    lo, hi = ra["window_start_epoch"].min(), ra["window_end_epoch"].max() + 120
    rh = heals[(heals["emitted_at_epoch"] >= lo) & (heals["emitted_at_epoch"] <= hi)] if len(heals) else heals
    st.altair_chart(timeline(ra, rh, t), width="stretch", key="timeline")
    st.markdown('<div class="pd pd-note">Each dot is one 5-second window. Shaded bands are the policy: observe below %d, '
                'rate-limit %d–%d, quarantine above %d. Green diamonds mark a finished heal.</div>'
                % (OBSERVE_BELOW, OBSERVE_BELOW, QUARANTINE_ABOVE, QUARANTINE_ABOVE), unsafe_allow_html=True)

    st.write("")
    c1, c2 = st.columns([1, 1], gap="large")
    with c1:
        why_panel(last, t)
    with c2:
        held_panel(held, t)
    st.write("")
    heal_history(heals, t)
    st.write("")
    recent_actions(alerts, t)
    st.markdown('<div class="pd pd-note" style="margin-top:1rem">Data: %s · refreshes every %d s · times in UTC</div>'
                % (html.escape(DB_PATH), REFRESH_SECONDS), unsafe_allow_html=True)


live()
