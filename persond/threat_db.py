#!/usr/bin/env python3
"""threat_db.py - the logbook. Saves every alert, decision, heal, escalation and containment
action in one SQLite file (threat.db). SQLite is built into Python - nothing to install.

Tables
  alerts        one row per window alert, key = alert_id (saving the same alert twice is ignored)
  actions       what the policy engine decided for each alert, and why
  heals         every restore: device, trigger risk, ok, seconds, verify_status
                (pending / verified / reinfected / unverified / failed)
  device_state  devices HELD for a human (status 'held'), or 'cleared' with the time a human cleared them
  escalations   every escalation ever: kind 'hold' (auto-reset stopped) or 'notify' (human told, nothing stopped),
                and when / by whom it was cleared
  containment   every isolate / release / rate-limit: mode (print or ryu), ok, rule verified, seconds
  indicators    indicators of compromise: the features that RAISED risk in each rate-limited / quarantined alert
  health        raw 'health' records from Person A's watchdog (format not fixed yet, stored as JSON)

An older threat.db is upgraded automatically (missing columns / tables are added).

  python persond/threat_db.py samples/SYNTHETIC_risk_ladder.jsonl          # load + decide + save (no healing)
  python persond/threat_db.py --show                                      # print what is stored
"""
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alert_reader import read_alerts  # noqa: E402
from policy import decide  # noqa: E402

DEFAULT_DB = "threat.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, device_ip TEXT, window_start_epoch REAL, window_end_epoch REAL,
    emitted_at_epoch REAL, threat_label TEXT, threat_probability REAL, risk_score INTEGER,
    p_xgboost REAL, p_incremental REAL, top_feature TEXT, explanation_json TEXT,
    fingerprint_schema TEXT, detector_action TEXT, synthetic INTEGER DEFAULT 0,
    firmware_id TEXT);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT UNIQUE REFERENCES alerts(alert_id),
    device_ip TEXT, action TEXT, reason TEXT, decided_at_epoch REAL);
CREATE TABLE IF NOT EXISTS heals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, ok INTEGER, exit_code TEXT,
    restore_seconds REAL, window_end_epoch REAL, emitted_at_epoch REAL, source TEXT,
    verify_status TEXT DEFAULT 'pending', trigger_risk INTEGER,
    UNIQUE (device_ip, emitted_at_epoch));
CREATE TABLE IF NOT EXISTS device_state (
    device_ip TEXT PRIMARY KEY, status TEXT, reason TEXT, since_epoch REAL);
CREATE TABLE IF NOT EXISTS escalations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, kind TEXT, reason TEXT, at_epoch REAL,
    cleared_at_epoch REAL, cleared_by TEXT);
CREATE TABLE IF NOT EXISTS containment (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, action TEXT, mode TEXT, ok INTEGER,
    verified INTEGER, seconds REAL, at_epoch REAL, detail TEXT);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, device_ip TEXT, feature TEXT, value REAL,
    impact REAL, monitor TEXT, UNIQUE (alert_id, feature));
CREATE TABLE IF NOT EXISTS health (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, emitted_at_epoch REAL, raw_json TEXT);
"""

# columns added after the first version of a table: (table, column, type)
UPGRADES = [("heals", "verify_status", "TEXT DEFAULT 'pending'"),
            ("heals", "trigger_risk", "INTEGER"),
            ("alerts", "firmware_id", "TEXT")]


class ThreatDatabase:
    def __init__(self, path=DEFAULT_DB):
        self.con = sqlite3.connect(path, timeout=10)    # timeout: the dashboard may be reading at the same time
        self.con.executescript(SCHEMA)
        for table, col, typ in UPGRADES:                # a threat.db from an earlier step
            cols = [r[1] for r in self.con.execute("PRAGMA table_info(%s)" % table)]
            if col not in cols:
                self.con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
        self.con.commit()

    # ---- alerts and decisions ------------------------------------------------------------
    def insert_alert(self, a):
        """Save one window alert. Returns True if new, False if it was already stored."""
        cur = self.con.execute(
            "INSERT OR IGNORE INTO alerts (alert_id, device_ip, window_start_epoch, window_end_epoch, "
            "emitted_at_epoch, threat_label, threat_probability, risk_score, p_xgboost, p_incremental, "
            "top_feature, explanation_json, fingerprint_schema, detector_action, synthetic, firmware_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["alert_id"], a.get("device_ip"), a["window_start_epoch"], a["window_end_epoch"],
             a["emitted_at_epoch"], a["threat_label"], a["threat_probability"], a["risk_score"],
             a.get("p_xgboost"), a.get("p_incremental"),
             a["explanation"][0]["feature"] if a["explanation"] else None,
             json.dumps(a["explanation"]), a.get("fingerprint_schema"), a["detector_action"],
             1 if a.get("synthetic") else 0, a.get("firmware_id")))
        self.con.commit()
        return cur.rowcount == 1

    def record_action(self, a, action, reason):
        self.con.execute("INSERT OR IGNORE INTO actions (alert_id, device_ip, action, reason, decided_at_epoch) "
                         "VALUES (?,?,?,?,?)", (a["alert_id"], a.get("device_ip"), action, reason, time.time()))
        self.con.commit()

    def record_indicators(self, a):
        """Indicators of compromise: the features that raised risk in this alert."""
        for e in a["explanation"]:
            if e["impact"] > 0:
                self.con.execute("INSERT OR IGNORE INTO indicators (alert_id, device_ip, feature, value, impact, monitor) "
                                 "VALUES (?,?,?,?,?,?)", (a["alert_id"], a.get("device_ip"), e["feature"],
                                                          e["value"], e["impact"], e.get("monitor")))
        self.con.commit()

    # ---- heals ---------------------------------------------------------------------------
    def record_heal(self, h, source="detector", trigger_risk=None):
        """source = 'detector' (heal record from the feed) or 'healing_engine' (our own restore).
        Returns the heal's row id (None if it was already stored)."""
        if trigger_risk is None and h.get("window_end_epoch") is not None:   # look up the window that caused it
            r = self.con.execute("SELECT risk_score FROM alerts WHERE device_ip = ? AND ABS(window_end_epoch - ?) < 0.01",
                                 (h.get("device_ip"), h["window_end_epoch"])).fetchone()
            trigger_risk = r[0] if r else None
        cur = self.con.execute("INSERT OR IGNORE INTO heals (device_ip, ok, exit_code, restore_seconds, window_end_epoch, "
                               "emitted_at_epoch, source, verify_status, trigger_risk) VALUES (?,?,?,?,?,?,?,?,?)",
                               (h.get("device_ip"), 1 if h["ok"] else 0, str(h.get("exit_code")), h["restore_seconds"],
                                h.get("window_end_epoch"), h["emitted_at_epoch"], source,
                                "pending" if h["ok"] else "failed", trigger_risk))
        self.con.commit()
        return cur.lastrowid if cur.rowcount == 1 else None

    def set_verify(self, heal_id, status):
        self.con.execute("UPDATE heals SET verify_status = ? WHERE id = ?", (status, heal_id))
        self.con.commit()

    def heals_between(self, device_ip, start_epoch, end_epoch):
        """Number of heals of this device that finished between the two times (alert clock)."""
        return self.con.execute("SELECT COUNT(*) FROM heals WHERE device_ip = ? AND emitted_at_epoch BETWEEN ? AND ?",
                                (device_ip, start_epoch, end_epoch)).fetchone()[0]

    # ---- escalation and holding ----------------------------------------------------------
    def escalate(self, device_ip, kind, reason, at):
        """kind 'hold' = stop auto-reset and hold for a human; 'notify' = tell a human, change nothing else."""
        self.con.execute("INSERT INTO escalations (device_ip, kind, reason, at_epoch) VALUES (?,?,?,?)",
                         (device_ip, kind, reason, at))
        if kind == "hold":
            self.con.execute("INSERT OR REPLACE INTO device_state VALUES (?, 'held', ?, ?)", (device_ip, reason, at))
        self.con.commit()

    def hold(self, device_ip, reason, at):
        self.escalate(device_ip, "hold", reason, at)

    def clear(self, device_ip, by="human"):
        """Release a held device. Its heal count starts fresh from now (on the alert clock)."""
        if not self.held_reason(device_ip):
            return False
        last = self.con.execute("SELECT MAX(window_end_epoch) FROM alerts WHERE device_ip = ?", (device_ip,)).fetchone()[0]
        held_since = self.con.execute("SELECT since_epoch FROM device_state WHERE device_ip = ?", (device_ip,)).fetchone()[0]
        at = max(x for x in (last, held_since, 0) if x is not None)
        self.con.execute("INSERT OR REPLACE INTO device_state VALUES (?, 'cleared', ?, ?)",
                         (device_ip, "cleared by " + by, at))
        self.con.execute("UPDATE escalations SET cleared_at_epoch = ?, cleared_by = ? "
                         "WHERE device_ip = ? AND cleared_at_epoch IS NULL", (at, by, device_ip))
        self.con.commit()
        return True

    def held_reason(self, device_ip):
        r = self.con.execute("SELECT reason FROM device_state WHERE device_ip = ? AND status = 'held'",
                             (device_ip,)).fetchone()
        return r[0] if r else None

    def cleared_at(self, device_ip):
        """When a human last cleared this device (alert clock), or 0."""
        r = self.con.execute("SELECT since_epoch FROM device_state WHERE device_ip = ? AND status = 'cleared'",
                             (device_ip,)).fetchone()
        return r[0] if r else 0

    def escalated_since(self, device_ip, since_epoch, until_epoch):
        return self.con.execute("SELECT COUNT(*) FROM escalations WHERE device_ip = ? AND at_epoch BETWEEN ? AND ?",
                                (device_ip, since_epoch, until_epoch)).fetchone()[0]

    # ---- containment and health ----------------------------------------------------------
    def record_containment(self, device_ip, action, mode, ok, verified, seconds, at, detail=""):
        self.con.execute("INSERT INTO containment (device_ip, action, mode, ok, verified, seconds, at_epoch, detail) "
                         "VALUES (?,?,?,?,?,?,?,?)", (device_ip, action, mode, 1 if ok else 0,
                                                      None if verified is None else (1 if verified else 0),
                                                      seconds, at, detail))
        self.con.commit()

    def record_health(self, h):
        self.con.execute("INSERT INTO health (device_ip, emitted_at_epoch, raw_json) VALUES (?,?,?)",
                         (h.get("device_ip"), h.get("emitted_at_epoch"), json.dumps(h)))
        self.con.commit()

    # ---- generic ---------------------------------------------------------------------------
    def count(self, table):
        return self.con.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]

    def rows(self, sql, args=()):
        return self.con.execute(sql, args).fetchall()


def load(db, lines):
    """Read alerts, decide each one, save everything (no healing). Returns (new_alerts, duplicates)."""
    new = dup = 0
    for a in read_alerts(lines, on_bad=lambda n, why: print("SKIPPED line %d: %s" % (n, why), file=sys.stderr)):
        if a["type"] == "heal":
            db.record_heal(a)
            continue
        if a["type"] == "health":
            db.record_health(a)
            continue
        if db.insert_alert(a):
            new += 1
            action, reason = decide(a)
            db.record_action(a, action, reason)
        else:
            dup += 1
    return new, dup


def show(db):
    print("alerts %d | actions %d | heals %d | escalations %d | containment %d | indicators %d" % (
        db.count("alerts"), db.count("actions"), db.count("heals"), db.count("escalations"),
        db.count("containment"), db.count("indicators")))
    print("\nactions by type:")
    for action, n in db.rows("SELECT action, COUNT(*) FROM actions GROUP BY action ORDER BY action"):
        print("  %-11s %d" % (action, n))
    print("\nnon-observe decisions:")
    for r in db.rows("SELECT a.risk_score, a.threat_label, x.action, a.top_feature, a.alert_id FROM actions x "
                     "JOIN alerts a USING (alert_id) WHERE x.action NOT IN ('observe', 'ignored') "
                     "ORDER BY a.window_start_epoch"):
        print("  risk %3d  %-10s -> %-10s top=%s  (%s)" % r)
    print("\nheals:")
    for r in db.rows("SELECT device_ip, trigger_risk, ok, restore_seconds, source, verify_status FROM heals "
                     "ORDER BY emitted_at_epoch"):
        print("  %s trigger risk %s ok=%s %.1f s (%s) -> %s" % (r[0], r[1], bool(r[2]), r[3], r[4], r[5]))
    print("\nescalations:")
    for r in db.rows("SELECT device_ip, kind, reason, cleared_by FROM escalations ORDER BY at_epoch"):
        print("  %s %s: %s%s" % (r[0], r[1], r[2], "  (cleared by %s)" % r[3] if r[3] else ""))
    held = db.rows("SELECT device_ip, reason FROM device_state WHERE status = 'held'")
    print("\ndevices held for a human:", held if held else "none")


def main():
    args = sys.argv[1:]
    db = ThreatDatabase(os.environ.get("THREAT_DB", DEFAULT_DB))
    if args == ["--show"]:
        show(db)
        return
    files = args or ["-"]
    for path in files:
        src = sys.stdin if path == "-" else open(path)
        new, dup = load(db, src)
        print("%s: %d new alerts saved, %d already stored" % (path, new, dup))
    show(db)


if __name__ == "__main__":
    main()
