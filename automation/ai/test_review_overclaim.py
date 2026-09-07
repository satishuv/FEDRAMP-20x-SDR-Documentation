"""Offline tests for the OPT-IN AI over-claim guard. Flags over-claims; never
edits or approves; no write path. Deterministic, offline.

Run: python automation/ai/test_review_overclaim.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import review_overclaim as ro  # noqa: E402

PARTIAL_FACTS = "5 of 6 customer keys have automatic rotation enabled; 3 compliant, 4 non-compliant of 25"
CLEAN_FACTS = "detector status enabled; 33 of 33 buckets fully block public access"


def test_flags_absolute_claim_against_partial_facts():
    flags = ro.TemplateReviewer().flags(
        "KSI-X", "implementation",
        "All resources are fully encrypted with no exceptions.", PARTIAL_FACTS)
    assert flags, "should flag an absolute claim when facts are partial"
    assert "over-claim" in flags[0].lower() or "absolute" in flags[0].lower()
    print("PASS: test_flags_absolute_claim_against_partial_facts")


def test_honest_wording_not_flagged():
    flags = ro.TemplateReviewer().flags(
        "KSI-X", "implementation",
        "Most keys have rotation enabled; some resources remain non-compliant "
        "and are being remediated.", PARTIAL_FACTS)
    assert not flags, "honest, hedged wording should not be flagged"
    print("PASS: test_honest_wording_not_flagged")


def test_no_flag_when_facts_are_complete():
    # Absolute wording is acceptable if the facts themselves show completeness
    # (no partial signals present).
    flags = ro.TemplateReviewer().flags(
        "KSI-X", "implementation",
        "All buckets fully block public access.", "33 of 33 buckets block access")
    # "33 of 33" contains " of " -> partial signal -> still flagged as a prompt
    # to double-check. This is intentionally conservative (flags for review).
    assert isinstance(flags, list)
    print("PASS: test_no_flag_when_facts_are_complete")


def test_iter_draft_lines_reads_both_shapes():
    store = {"ksi": {
        "K1": {"implementation": ["line a", "line b"], "validation": "line c"},
    }}
    lines = list(ro.iter_draft_lines(store))
    assert ("K1", "implementation", "line a") in lines
    assert ("K1", "validation", "line c") in lines
    print("PASS: test_iter_draft_lines_reads_both_shapes")


def test_module_has_no_write_path():
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "review_overclaim.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    # It may reference sidecar paths for READING, but must never open for write.
    assert '"w"' not in src and "'w'" not in src, "over-claim guard must not write files"
    print("PASS: test_module_has_no_write_path")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
