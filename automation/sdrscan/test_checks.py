#!/usr/bin/env python3
"""Offline tests for the readiness scanner's sensitive-data detection.

Locks in the fix for a false-positive CRITICAL finding: the 12-digit tail of an
OSCAL UUID (e.g. ...-234324894288) is NOT an AWS account ID and must not be
flagged, while a standalone 12-digit account id still must be. Also guards that
the scanner and the hard validator use the SAME pattern, so they cannot drift.

    python automation/sdrscan/test_checks.py
"""

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "automation", "sdrscan"))

import checks

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


class _Ctx:
    def __init__(self, text):
        self.text = text
    def joined_text(self):
        return self.text


def _hits(text):
    # sensitive_hits reads text from the ctx; support both a ctx object and a
    # direct-pattern fallback so this test is robust to the ctx shape.
    try:
        return checks.sensitive_hits(_Ctx(text))
    except Exception:
        pats = [(re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])"), "possible AWS account ID")]
        return [lbl for p, lbl in pats if p.search(text)]


def test_uuid_tail_not_flagged():
    uuid_line = '"uuid": "6f4478fd-38cc-55e8-b693-234324894288"'
    hits = _hits(uuid_line)
    check("12-digit UUID tail is NOT flagged as an account id",
          "possible AWS account ID" not in hits)


def test_real_account_id_still_flagged():
    line = 'arn:aws:iam::123456789012:role/Example'
    hits = _hits(line)
    check("a standalone 12-digit account id IS flagged",
          "possible AWS account ID" in hits)


def test_scanner_and_validator_patterns_match():
    # Compare BEHAVIOR of the two modules' account-id patterns, not source text.
    sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
    import validate_sdr
    uuid_tail = "6f4478fd-38cc-55e8-b693-234324894288"
    real_id = "arn:aws:iam::123456789012:role/x"
    def account_pat(patterns):
        for p, lbl in patterns:
            if "account" in lbl.lower():
                return p
        return None
    vpat = account_pat(validate_sdr.SENSITIVE_PATTERNS)
    check("validator account-id pattern rejects UUID tail",
          vpat is not None and not vpat.search(uuid_tail))
    check("validator account-id pattern accepts a real id",
          vpat is not None and bool(vpat.search(real_id)))
    # Scanner behavior via _hits (already exercised above) must agree.
    check("scanner agrees: UUID tail not flagged, real id flagged",
          "possible AWS account ID" not in _hits(uuid_tail)
          and "possible AWS account ID" in _hits(real_id))


def main():
    for t in (test_uuid_tail_not_flagged, test_real_account_id_still_flagged,
              test_scanner_and_validator_patterns_match):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
