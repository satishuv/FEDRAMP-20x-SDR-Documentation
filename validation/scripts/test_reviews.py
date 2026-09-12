#!/usr/bin/env python3
"""Offline tests for the review-register validator invariants. Run:
    python validation/scripts/test_reviews.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate_reviews as vr  # noqa: E402


def _check(reviews, graph_ids=None):
    """Re-implement the core loop against an in-memory register so the test
    does not depend on files. Returns the problem list."""
    problems = []
    for i, r in enumerate(reviews):
        where = r.get("review_id", f"#{i}")
        for f in vr.REQUIRED:
            if not r.get(f):
                problems.append(f"{where}: missing {f}")
        dec = r.get("decision")
        if dec and dec not in vr.ALLOWED_DECISIONS:
            problems.append(f"{where}: bad decision")
        if str(r.get("reviewer", "")).strip().lower() in vr.FORBIDDEN_REVIEWERS:
            problems.append(f"{where}: non-human reviewer")
        if dec == "approved" and not r.get("evidence_hashes_reviewed"):
            problems.append(f"{where}: approved without evidence")
    return problems


def test_empty_register_is_valid():
    assert _check([]) == []


def test_good_human_review_passes():
    r = {"review_id": "REV-1", "assurance_id": "FRC-CSO-PKG", "reviewer": "Jane Doe",
         "role": "Security Reviewer", "decision": "approved",
         "reviewed_at": "2026-09-12T18:00:00Z",
         "evidence_hashes_reviewed": ["sha256:abc"]}
    assert _check([r]) == []


def test_machine_reviewer_rejected():
    for bad in ("deterministic", "pipeline", "system", "bot", ""):
        r = {"review_id": "REV-2", "assurance_id": "FRC-CSO-PKG", "reviewer": bad,
             "role": "x", "decision": "approved", "reviewed_at": "t",
             "evidence_hashes_reviewed": ["sha256:abc"]}
        probs = _check([r])
        assert any("non-human" in p for p in probs), f"{bad} should be rejected"


def test_approved_without_evidence_rejected():
    r = {"review_id": "REV-3", "assurance_id": "FRC-CSO-PKG", "reviewer": "Jane",
         "role": "x", "decision": "approved", "reviewed_at": "t"}
    assert any("without evidence" in p for p in _check([r]))


def test_bad_decision_rejected():
    r = {"review_id": "REV-4", "assurance_id": "FRC-CSO-PKG", "reviewer": "Jane",
         "role": "x", "decision": "certified", "reviewed_at": "t",
         "evidence_hashes_reviewed": ["sha256:abc"]}
    assert any("bad decision" in p for p in _check([r]))


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
