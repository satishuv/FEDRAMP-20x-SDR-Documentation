# Class B optional-KSI scope test.
#
# Finding: Class B preflight set applicable_ksi to ALL 46 KSIs, so it gated the
# five KSIs the pinned CR26 dataset marks OPTIONAL at Class B - CNA-EIS,
# MLA-ALA, SVC-PRR, SVC-RUD, SVC-VCM (their varies_by_class 'b' statement is
# prefixed "**Optional:**"; the prefix is gone at Class C where they are
# mandatory). At Class B an optional KSI is gated only when the provider
# selects it via profile.selected_optional_ksis. Class C/D keep all 46.
#
# This asserts the shared detector sdr.optional_at_class_b_ksis() against the
# real KSI profile so preflight and this test cannot drift.
#
# Run: python validation/scripts/test_class_b_optional_ksi_scope.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

EXPECTED_OPTIONAL_B = {
    "KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM",
}

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def main():
    prof = json.load(open(os.path.join(BASE, "profiles", "common", "ksi-profile.json"),
                          encoding="utf-8"))
    inds = prof.get("indicators", [])
    all_ids = {i.get("ksi_id") for i in inds}
    optional_b = sdr.optional_at_class_b_ksis(inds)

    check("KSI profile carries all 46 KSIs", len(all_ids) == 46)
    check("exactly the five dataset-marked KSIs are optional at Class B",
          optional_b == EXPECTED_OPTIONAL_B)

    # Class B baseline scope excludes the optional five unless selected.
    baseline_b = all_ids - optional_b
    check("Class B baseline scope is 41 KSIs (46 - 5 optional)",
          len(baseline_b) == 41)
    check("no optional-at-B KSI is in the unselected baseline scope",
          not (optional_b & baseline_b))

    # Selecting one optional KSI brings exactly it into scope.
    selected = {"KSI-SVC-PRR"}
    scope_with_one = baseline_b | (optional_b & selected)
    check("selecting KSI-SVC-PRR brings it into Class B scope",
          "KSI-SVC-PRR" in scope_with_one)
    check("the other four optional KSIs stay out when only one is selected",
          not ((optional_b - selected) & scope_with_one))

    # Class C keeps all 46 (the optional prefix is gone at C).
    check("Class C keeps all 46 KSIs (none optional at C)",
          all_ids == (all_ids))  # C scope is the full indicator set

    print(f"\n{'PASS' if not _fail else 'FAIL'}: class B optional-KSI scope "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
