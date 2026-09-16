#!/usr/bin/env python3
"""Offline tests for the change-impact engine. No network. Run:
    python validation/scripts/test_change_impact.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import change_impact as ci  # noqa: E402


def _real_class_c_rule():
    """Pick a rule id that is actually in the Class C profile, so impact
    resolution has something to resolve against."""
    import json
    prof = json.load(open(os.path.join(ci.BASE, "profiles", "class-c", "profile.json"),
                          encoding="utf-8"))
    return prof["rules"][0]["rule_id"]


def test_force_escalation_to_must_requires_review():
    rid = _real_class_c_rule()
    diff = {"rules_added": [], "rules_removed": [],
            "rules_changed": [{"id": rid, "changes": {"force": {"old": "SHOULD", "new": "MUST"}}}],
            "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == rid)
    assert imp["force_escalation_to_must"] is True
    assert imp["requires_human_review"] is True
    assert "C" in imp["affected_classes"]
    assert any("sdr-class-c.json" in o for o in imp["affected_outputs"])


def test_removed_rule_always_requires_review():
    diff = {"rules_added": [], "rules_removed": ["ZZZ-ZZZ-ZZZ"],
            "rules_changed": [], "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == "ZZZ-ZZZ-ZZZ")
    assert imp["change_type"] == "removed"
    assert imp["requires_human_review"] is True


def test_statement_change_on_in_scope_rule():
    rid = _real_class_c_rule()
    diff = {"rules_added": [], "rules_removed": [],
            "rules_changed": [{"id": rid, "changes": {"statement": {"old": "a", "new": "b"}}}],
            "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == rid)
    assert imp["requires_human_review"] is True
    assert imp["change_detail"]["statement"]["new"] == "b"


def test_out_of_scope_change_has_no_class_impact():
    diff = {"rules_added": [], "rules_removed": [],
            "rules_changed": [{"id": "QQQ-QQQ-QQQ", "changes": {"force": {"old": "MAY", "new": "SHOULD"}}}],
            "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == "QQQ-QQQ-QQQ")
    assert imp["affected_classes"] == []
    assert imp["affected_outputs"] == []


def test_definition_change_requires_review():
    # A controlled FedRAMP definition (FRD) change must produce a review item,
    # not be silently ignored (it can shift the meaning of every rule using it).
    diff = {"rules_added": [], "rules_removed": [], "rules_changed": [],
            "ksis_added": [], "ksis_removed": [], "ksis_changed": [],
            "definitions_added": ["FRD-MST"], "definitions_removed": [],
            "definitions_changed": ["FRD-SHD"], "summary": {}}
    out = ci.compute(diff)
    assert out.get("definition_impacts"), "definition changes produced no impact"
    ids = {i["definition_id"] for i in out["definition_impacts"]}
    assert {"FRD-MST", "FRD-SHD"} <= ids
    assert all(i["requires_human_review"] for i in out["definition_impacts"])
    assert out["total_requiring_review"] >= 2


def test_applicability_change_forces_review_even_if_out_of_scope():
    # A rule that changed applicability but is not in any current profile must
    # still require review (old union new applicability), not be dropped.
    diff = {"rules_added": [], "rules_removed": [],
            "rules_changed": [{"id": "QQQ-QQQ-APP",
                               "changes": {"applicability": {"old": "20x", "new": "rev5"}}}],
            "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == "QQQ-QQQ-APP")
    assert imp["requires_human_review"] is True
    assert imp.get("applicability_or_class_variance_changed") is True


def test_varies_by_class_loss_reports_old_union_new_classes():
    # A rule that USED to vary by (and apply to) Class A but no longer does:
    # current-profile membership would report [], under-reporting the impact.
    # affected_classes must union in the class named on the OLD side, and the
    # report must flag that the class list may be incomplete.
    diff = {"rules_added": [], "rules_removed": [],
            "rules_changed": [{"id": "ZZZ-ZZZ-VBC",
                               "changes": {"varies_by_class": {
                                   "old": {"a": "SHOULD", "b": "MUST"},
                                   "new": {"b": "MUST"}}}}],
            "summary": {}}
    out = ci.compute(diff)
    imp = next(i for i in out["impacts"] if i["rule_id"] == "ZZZ-ZZZ-VBC")
    assert imp["requires_human_review"] is True
    assert "A" in imp["affected_classes"]  # old-side class is not dropped
    assert imp.get("affected_classes_may_be_incomplete") is True


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
