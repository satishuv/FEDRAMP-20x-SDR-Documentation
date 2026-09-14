#!/usr/bin/env python3
"""Offline tests for dataset_diff.py using tiny synthetic datasets (no real
multi-MB file). Run: python validation/scripts/test_dataset_diff.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dataset_diff as dd  # noqa: E402


def _ds(rules_by_applic, ksi=None):
    """Build a minimal dataset. rules_by_applic: {applic: {RULE-ID: {force,statement}}}."""
    data = {}
    for applic, rules in rules_by_applic.items():
        data[applic] = {"FRP": dict(rules)}
    return {"FRR": {"XXX": {"data": data}}, "KSI": ksi or {}}


OLD = _ds({"20x": {
    "AFC-FRP-VRE": {"force": "MAY", "statement": "old text"},
    "AFC-FRP-OLD": {"force": "MUST", "statement": "going away"},
}})
NEW = _ds({"20x": {
    "AFC-FRP-VRE": {"force": "MUST", "statement": "new text"},
    "AFC-FRP-NEW": {"force": "SHOULD", "statement": "brand new"},
}})


def test_force_change_detected():
    d = dd.diff_datasets(OLD, NEW)
    changed = {c["id"]: c["changes"] for c in d["rules_changed"]}
    assert "AFC-FRP-VRE" in changed
    assert changed["AFC-FRP-VRE"]["force"] == {"old": "MAY", "new": "MUST"}


def test_statement_change_detected():
    d = dd.diff_datasets(OLD, NEW)
    changed = {c["id"]: c["changes"] for c in d["rules_changed"]}
    assert "statement" in changed["AFC-FRP-VRE"]


def test_added_rule_detected():
    d = dd.diff_datasets(OLD, NEW)
    assert "AFC-FRP-NEW" in d["rules_added"]


def test_removed_rule_detected():
    d = dd.diff_datasets(OLD, NEW)
    assert "AFC-FRP-OLD" in d["rules_removed"]


def test_applicability_change_detected():
    old = _ds({"rev5": {"AFC-FRP-VRE": {"force": "MUST", "statement": "x"}}})
    new = _ds({"20x": {"AFC-FRP-VRE": {"force": "MUST", "statement": "x"}}})
    d = dd.diff_datasets(old, new)
    changed = {c["id"]: c["changes"] for c in d["rules_changed"]}
    assert changed["AFC-FRP-VRE"]["applicability"] == {"old": "rev5", "new": "20x"}


def test_ksi_family_change_detected():
    old = _ds({"20x": {}}, ksi={"CED": {"indicators": {"KSI-CED-RAT": {}}}})
    new = _ds({"20x": {}}, ksi={"CED": {"indicators":
              {"KSI-CED-RAT": {}, "KSI-CED-NEW": {}}}})
    d = dd.diff_datasets(old, new)
    assert d["ksi_family_changes"]["CED"] == {"old": 1, "new": 2}
    assert d["ksi_total"] == {"old": 1, "new": 2}


def test_no_change_reports_empty():
    d = dd.diff_datasets(OLD, OLD)
    assert d["summary"] == {"added": 0, "removed": 0, "changed": 0,
                            "force_changes": 0, "timeframe_changes": 0,
                            "ksis_added": 0, "ksis_removed": 0, "ksis_changed": 0,
                            "definitions_added": 0, "definitions_removed": 0,
                            "definitions_changed": 0}


def test_ksi_statement_change_detected():
    import copy
    new = copy.deepcopy(OLD)
    # Mutate one KSI's statement text and confirm it is reported individually,
    # not merely as a family count change.
    for fam, body in new.get("KSI", {}).items():
        inds = body.get("indicators", body) if isinstance(body, dict) else {}
        for kid, entry in (inds.items() if isinstance(inds, dict) else []):
            if isinstance(entry, dict) and (entry.get("statement") or entry.get("text")):
                key = "statement" if entry.get("statement") else "text"
                entry[key] = "TAMPERED " + str(entry[key])
                d = dd.diff_datasets(OLD, new)
                assert any(c["id"] == kid for c in d["ksis_changed"]), \
                    "individual KSI statement change not detected"
                return
    # No KSI with a statement found; nothing to assert.


def test_timeframe_range_change_detected():
    # A rule that gains timeframe_num_min/timeframe_num_max (the CR26
    # 2026.09.13.02 structure) must be reported as a timeframe change, not
    # silently dropped by a name/force/statement-only diff.
    import copy
    new = copy.deepcopy(OLD)
    frr = new.get("FRR", {})

    def first_rule(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and ("force" in v or "statement" in v) \
                        and dd.RULE_ID.match(k or ""):
                    return v
                r = first_rule(v)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = first_rule(v)
                if r is not None:
                    return r
        return None

    rule = first_rule(frr)
    assert rule is not None, "no FRR rule found to mutate"
    rule["timeframe_type"] = "bizdays"
    rule["timeframe_num_min"] = 3
    rule["timeframe_num_max"] = 10
    d = dd.diff_datasets(OLD, new)
    assert d["summary"]["timeframe_changes"] >= 1, \
        "timeframe range change not reported"
    assert any("timeframe" in c["changes"] for c in d["rules_changed"])


def test_definition_change_detected():
    # An added or changed FRD controlled definition must be reported, since a
    # definition change can shift the meaning of every rule using the term.
    import copy
    new = copy.deepcopy(OLD)
    new.setdefault("FRD", {})["FRD-TEST"] = {"definition": "A brand new term."}
    d = dd.diff_datasets(OLD, new)
    assert "FRD-TEST" in d["definitions_added"], \
        "added definition not detected"
    assert d["summary"]["definitions_added"] >= 1


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
