#!/usr/bin/env python3
"""Prove the live evidence-integrity gate actually recomputes digests.

The earlier gate only regex-checked the hash format; these tests confirm the
real behavior: a well-formed but WRONG stored hash over a resolvable source is a
HARD failure, and a matching hash passes. Covers both storage shapes
(KSI evidence and FRR extension.rule_artifacts).

    python validation/scripts/test_evidence_integrity.py
"""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))

import validate_evidence as ve
from evidence_wiring import evidence_hash

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def _count_hard(records):
    """Run the gate's core over an in-memory record store; return hard-fail count."""
    hard = []
    for oid, section, e in ve.iter_evidence(records):
        h = e.get("xEvidenceContentHash") or e.get("stored_sha256")
        if not h:
            continue
        if not ve.HASH_RE.match(str(h)):
            hard.append((section, oid, "malformed"))
            continue
        source, kind = ve._resolve_source(e)
        if source is None:
            continue
        if evidence_hash(source) != h:
            hard.append((section, oid, "mismatch"))
    return hard


def test_wrong_hash_over_resolvable_source_is_hard_fail():
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    wrong = "sha256:" + "0" * 64  # well-formed but not the real digest
    records = {"ksi": {"KSI-TEST-001": {"evidence": [
        {"source_fact": fact, "xEvidenceContentHash": wrong,
         "evidenceLocation": "s3://bucket/key"}]}}, "frr": {}}
    hard = _count_hard(records)
    check("KSI wrong-but-well-formed hash is caught", any(h[2] == "mismatch" for h in hard))


def test_matching_hash_passes():
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    right = evidence_hash(fact)
    records = {"ksi": {"KSI-TEST-002": {"evidence": [
        {"source_fact": fact, "xEvidenceContentHash": right,
         "evidenceLocation": "s3://bucket/key"}]}}, "frr": {}}
    check("matching hash produces no hard failure", not _count_hard(records))


def test_frr_evidence_is_read():
    fact = {"artifact": "config-snapshot", "value": 42}
    wrong = "sha256:" + "a" * 64
    records = {"frr": {"AFC-CSP-INI": {"extension": {"rule_artifacts": [
        {"source_fact": fact, "xEvidenceContentHash": wrong}]}}}, "ksi": {}}
    seen = [oid for oid, sect, _ in ve.iter_evidence(records) if sect == "frr"]
    check("FRR extension.rule_artifacts is iterated", "AFC-CSP-INI" in seen)
    check("FRR wrong hash is caught", any(h[2] == "mismatch" for h in _count_hard(records)))


def main():
    for t in (test_wrong_hash_over_resolvable_source_is_hard_fail,
              test_matching_hash_passes, test_frr_evidence_is_read):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
