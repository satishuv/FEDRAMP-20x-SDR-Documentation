#!/usr/bin/env python3
"""Prove the applicability decisions reconcile with the actual class profile.

Every rule the decisions mark 'applicable' must be in the class profile, and
every profile rule must be marked applicable. No rule may be silently missing
from the decision record. Also checks every excluded rule carries a non-empty
reason. Offline. Run:
    python validation/scripts/test_applicability.py
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_applicability_decisions as bad  # noqa: E402


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _decisions(cls):
    return bad.build(cls)


def test_included_matches_profile():
    for cls in ("a", "b", "c"):
        prof = _load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
        profile_ids = {r["rule_id"] for r in prof["rules"]}
        dec = _decisions(cls)
        included = {d["rule_id"] for d in dec["decisions"] if d["applicable"]}
        # Class A enumerates via CLA; the profile is authoritative. The decision
        # record's 'included' set must equal the profile rule set.
        missing = profile_ids - included
        extra = included - profile_ids
        assert not missing, f"class {cls}: profile rules missing from decisions: {sorted(missing)[:5]}"
        assert not extra, f"class {cls}: decisions include rules not in profile: {sorted(extra)[:5]}"


def test_every_excluded_has_a_reason():
    dec = _decisions("c")
    for d in dec["decisions"]:
        if not d["applicable"]:
            assert d["reason"] and d["reason"].strip(), f"{d['rule_id']} excluded with no reason"


def test_totals_reconcile():
    dec = _decisions("c")
    assert dec["included"] + dec["excluded"] == dec["total_rules"]
    assert dec["included"] == sum(1 for d in dec["decisions"] if d["applicable"])


def test_absence_is_provable():
    # Pick an excluded rule and confirm we can state why it is absent.
    dec = _decisions("c")
    excluded = [d for d in dec["decisions"] if not d["applicable"]]
    assert excluded, "expected some rules to be excluded at Class C"
    sample = excluded[0]
    assert sample["reason"], "an excluded rule must carry a provable reason"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
