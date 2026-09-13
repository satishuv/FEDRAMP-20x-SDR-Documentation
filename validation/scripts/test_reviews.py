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


def _run_main_with(register, graph):
    """Drive the real validate_reviews.main against temp register+graph files,
    so the node-evidence binding (only in main) is exercised. Returns exit code."""
    import json
    import tempfile
    d = tempfile.mkdtemp(prefix="rev-")
    rp = os.path.join(d, "review-register.json")
    gp = os.path.join(d, "assurance-graph.json")
    with open(rp, "w", encoding="utf-8") as f:
        json.dump(register, f)
    with open(gp, "w", encoding="utf-8") as f:
        json.dump(graph, f)
    saved_r, saved_g = vr.REGISTER, vr.GRAPH
    vr.REGISTER, vr.GRAPH = rp, gp
    try:
        return vr.main()
    finally:
        vr.REGISTER, vr.GRAPH = saved_r, saved_g


def _approved(hashes):
    return {"reviews": [{
        "review_id": "R1", "assurance_id": "KSI-IAM-AAM", "reviewer": "Jane, VP Sec",
        "role": "Security Lead", "decision": "approved",
        "reviewed_at": "2026-09-10T00:00:00+00:00",
        "evidence_hashes_reviewed": hashes,
    }]}


GOOD_HASH = "sha256:" + "a" * 64


def _graph_with_node_evidence(hashval):
    return {"nodes": [{"ksi_id": "KSI-IAM-AAM",
                       "evidence": [{"xEvidenceContentHash": hashval}]}]}


def test_node_review_matching_current_evidence_passes():
    code = _run_main_with(_approved([GOOD_HASH]), _graph_with_node_evidence(GOOD_HASH))
    assert code == 0, "an approved review whose hash matches the node's evidence must pass"


def test_node_review_stale_hash_is_rejected():
    stale = "sha256:" + "b" * 64
    code = _run_main_with(_approved([stale]), _graph_with_node_evidence(GOOD_HASH))
    assert code == 1, "a reviewed hash not matching the node's current evidence must fail"


def test_node_review_malformed_hash_is_rejected():
    code = _run_main_with(_approved(["not-a-hash"]), _graph_with_node_evidence(GOOD_HASH))
    assert code == 1, "a malformed evidence hash must fail"


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
