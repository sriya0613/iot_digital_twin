#!/usr/bin/env python3
"""Stand-in for Person 1's restore.sh so the loop can be tested without the twin.
Works on Windows, Linux and macOS. Same contract: exit code 0 = healed.
Appends a line to a log file so the tests can count the calls."""
import os
import sys
import tempfile
import time

log = os.environ.get("FAKE_RESTORE_LOG") or os.path.join(tempfile.gettempdir(), "fake_restore.log")
with open(log, "a") as f:
    f.write("%s restore called\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
time.sleep(float(os.environ.get("FAKE_RESTORE_SECONDS", "0")))
sys.exit(int(os.environ.get("FAKE_RESTORE_EXIT", "0")))
