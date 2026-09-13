#!/usr/bin/env python3
"""Mute-expiry enforcement test for the readiness scanner.

A mute must carry a justification AND an expiry, and an EXPIRED or unparseable
expiry must NOT suppress the finding (fail closed). Without this, an old
suppression would keep a real gap muted forever in a customer-facing report.

    python automation/sdrscan/test_mute_expiry.py
"""

import datetime
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sdrscan  # noqa: E402


def _write_mutelist(entries):
    d = tempfile.mkdtemp(prefix="mute-")
    path = os.path.join(d, "mutelist.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"mutes": entries}, f)
    return path


def main():
    today = datetime.date.today()
    future = (today + datetime.timedelta(days=30)).isoformat()
    past = (today - datetime.timedelta(days=1)).isoformat()
    entries = [
        {"check_id": "c_future", "resource_id": "r", "justification": "ok", "expires": future},
        {"check_id": "c_past", "resource_id": "r", "justification": "ok", "expires": past},
        {"check_id": "c_today", "resource_id": "r", "justification": "ok", "expires": today.isoformat()},
        {"check_id": "c_bad", "resource_id": "r", "justification": "ok", "expires": "not-a-date"},
        {"check_id": "c_noexp", "resource_id": "r", "justification": "ok"},
    ]
    saved = sdrscan.MUTELIST
    sdrscan.MUTELIST = _write_mutelist(entries)
    try:
        muted = sdrscan.load_mutelist()
    finally:
        sdrscan.MUTELIST = saved

    keys = {k[0] for k in muted}
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    check("a future-dated mute is honored", "c_future" in keys)
    check("a past-dated mute is NOT honored (expired)", "c_past" not in keys)
    check("a mute expiring today is NOT honored", "c_today" not in keys)
    check("an unparseable expiry is NOT honored (fail closed)", "c_bad" not in keys)
    check("a mute with no expiry is NOT honored", "c_noexp" not in keys)

    print(f"\n{passed}/{passed + failed} mute-expiry checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
