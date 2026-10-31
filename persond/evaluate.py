#!/usr/bin/env python3
"""evaluate.py - Person D's part of the evaluation table, computed from threat.db.

  python persond/evaluate.py                    # prints the report
  python persond/evaluate.py --out eval_report.md

What it can measure from threat.db alone:
  decisions per action, heals (count, success rate, restore time), verify outcomes,
  escalations, containment time (Ryu mode only), processing delay (live runs only).

What it can NOT measure without more data (said in the report too):
  - true false-positive rate and detection latency need the ground truth of when an attack really ran
    (Person B's data/run_manifest.jsonl on the twin host). Here the detector's own label is used as a stand-in.
"""
import argparse
import os
import sqlite3
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_db import ThreatDatabase  # noqa: E402


def stats(values):
    v = [x for x in values if x is not None]
    if not v:
        return "–"
    return "median %.2f s, min %.2f, max %.2f (n=%d)" % (statistics.median(v), min(v), max(v), len(v))


def report(path):
    ThreatDatabase(path).con.close()
    c = sqlite3.connect(path)
    q = lambda sql, *a: c.execute(sql, a).fetchall()   # noqa: E731
    one = lambda sql, *a: c.execute(sql, a).fetchone()[0]   # noqa: E731
    out = ["# Person D evaluation (from %s)" % path, ""]

    n = one("SELECT COUNT(*) FROM alerts")
    synth = one("SELECT COUNT(*) FROM alerts WHERE synthetic = 1")
    out += ["## Decisions", "", "| | count |", "|---|---|", "| alerts processed | %d (%d synthetic) |" % (n, synth)]
    for action, k in q("SELECT action, COUNT(*) FROM actions GROUP BY action ORDER BY COUNT(*) DESC"):
        out.append("| %s | %d |" % (action, k))
    benign_acted = one("SELECT COUNT(*) FROM alerts a JOIN actions x USING (alert_id) "
                       "WHERE a.threat_label = 'benign' AND x.action IN ('rate_limit', 'quarantine')")
    benign = one("SELECT COUNT(*) FROM alerts WHERE threat_label = 'benign'")
    out += ["| benign-labelled windows that were rate-limited or quarantined | %d of %d |" % (benign_acted, benign), ""]

    heals = q("SELECT source, ok, restore_seconds FROM heals")
    out += ["## Heals", "", "| | value |", "|---|---|", "| heals | %d |" % len(heals)]
    if heals:
        ok = sum(1 for h in heals if h[1])
        out.append("| success rate | %d / %d (%.0f%%) |" % (ok, len(heals), 100.0 * ok / len(heals)))
    for src, label in (("detector", "restore time, detector (real restore.sh)"),
                       ("healing_engine", "restore time, our engine")):
        out.append("| %s | %s |" % (label, stats([h[2] for h in heals if h[0] == src and h[1]])))
    for status, k in q("SELECT verify_status, COUNT(*) FROM heals GROUP BY verify_status ORDER BY verify_status"):
        out.append("| verify: %s | %d |" % (status, k))
    out.append("")

    out += ["## Escalations and containment", "", "| | value |", "|---|---|"]
    for kind, k in q("SELECT kind, COUNT(*) FROM escalations GROUP BY kind"):
        out.append("| escalations: %s | %d |" % (kind, k))
    if not one("SELECT COUNT(*) FROM escalations"):
        out.append("| escalations | 0 |")
    out.append("| held right now | %d |" % one("SELECT COUNT(*) FROM device_state WHERE status = 'held'"))
    ryu = q("SELECT action, ok, verified, seconds FROM containment WHERE mode = 'ryu'")
    if ryu:
        iso = [r[3] for r in ryu if r[0] == "isolate" and r[1]]
        out.append("| containment time (isolate rule added + verified) | %s |" % stats(iso))
        out.append("| containment steps verified on the switch | %d / %d |" % (sum(1 for r in ryu if r[2]), len(ryu)))
    else:
        out.append("| containment time | not measured: containment ran in print mode (laptop) |")
    out.append("")

    live = q("SELECT x.decided_at_epoch - a.emitted_at_epoch FROM actions x JOIN alerts a USING (alert_id) "
             "WHERE ABS(x.decided_at_epoch - a.emitted_at_epoch) < 60")
    out += ["## Processing delay", "",
            "Alert written by the detector -> decision stored: %s" % (
                stats([r[0] for r in live]) if live else "not measurable (replayed recordings, not a live run)"), ""]

    out += ["## Not measurable from threat.db", "",
            "- True false-positive rate and detection latency need the times an attack really ran "
            "(Person B's run_manifest.jsonl). The benign-label row above uses the detector's own label instead.",
            "- Restore times of 'our engine' on a laptop come from tests/fake_restore.py and mean nothing; "
            "use a live run on the twin host."]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.environ.get("THREAT_DB", "threat.db"))
    ap.add_argument("--out")
    a = ap.parse_args()
    if not os.path.exists(a.db):
        sys.exit("no database at %s - run the pipeline first" % a.db)
    text = report(a.db)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("\nsaved to %s" % a.out)


if __name__ == "__main__":
    main()
