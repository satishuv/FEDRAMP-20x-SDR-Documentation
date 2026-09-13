#!/usr/bin/env python3
"""Change Impact Engine.

Takes the structured diff from dataset_diff.py (rules added/removed/changed)
and computes the DOWNSTREAM impact of each change on this provider's package:

  changed FedRAMP rule
       -> affected certification classes (which class profiles include it)
       -> affected records-store entries
       -> affected evidence collectors (from the collector registry)
       -> affected generated SDR outputs
       -> requires_human_review

This is the difference between "the upstream rules moved" (drift detection,
which dataset_diff.py already does) and "here is exactly what in OUR package
must be re-reviewed as a result." It reads only local artifacts; it changes
nothing and sets no status.

Usage:
  python validation/scripts/change_impact.py OLD.json NEW.json [--json OUT.json]

Or against a precomputed diff:
  python validation/scripts/change_impact.py --diff diff.json [--json OUT.json]
"""

import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dataset_diff  # noqa: E402

CLASSES = ["a", "b", "c"]
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _class_rule_sets():
    """Which rules each class profile includes."""
    out = {}
    for cls in CLASSES:
        prof = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
        out[cls] = {r["rule_id"] for r in prof["rules"]} if prof else set()
    return out


def _ksi_collectors():
    """Map ksi_id -> the collector checks that produce its evidence, from the
    collector registry. Uses the registry structure the unused _collector_targets
    walked, but keyed by KSI so a changed KSI resolves to its collectors."""
    reg = load(REGISTRY, {"ksis": {}})
    out = {}
    for kid, entry in (reg.get("ksis", {}) or {}).items():
        checks = entry.get("checks", []) or []
        out[kid] = [c.get("check_id") or c.get("target") or c.get("check") or c.get("name")
                    for c in checks if isinstance(c, dict)]
    return out


def impact_for_rule(rid, change_type, class_sets, records):
    affected_classes = sorted(c.upper() for c in CLASSES if rid in class_sets[c])
    in_records = rid in (records.get("frr", {}) or {})
    affected_records = [f"sdr/records/records-store.json#/frr/{rid}"] if in_records else []
    affected_outputs = [f"sdr/json/sdr-class-{c}.json" for c in CLASSES
                        if rid in class_sets[c]]
    requires_review = bool(affected_classes) or change_type in ("removed",)
    return {
        "rule_id": rid,
        "change_type": change_type,
        "affected_classes": affected_classes,
        "affected_records": affected_records,
        "affected_outputs": affected_outputs,
        "requires_human_review": requires_review,
    }


def impact_for_ksi(kid, change_type, ksi_collectors, records):
    """Downstream impact of a changed KSI: changed KSI -> collector registry
    (which collectors feed it) -> evidence -> KSI SDR node. This chain is real
    because KSIs DO map to collectors in the registry; it does not invent an
    FRR->KSI relationship the dataset lacks."""
    collectors = ksi_collectors.get(kid, [])
    in_records = kid in (records.get("ksi", {}) or {})
    return {
        "ksi_id": kid,
        "change_type": change_type,
        "affected_collectors": collectors,
        "affected_records": [f"sdr/records/records-store.json#/ksi/{kid}"] if in_records else [],
        "affected_outputs": [f"sdr/json/sdr-class-{c}.json" for c in CLASSES],
        "requires_human_review": True,
    }


def compute(diff):
    class_sets = _class_rule_sets()
    records = load(RECORDS, {"frr": {}, "ksi": {}})
    ksi_collectors = _ksi_collectors()
    impacts = []
    ksi_impacts = []

    for rid in diff.get("rules_added", []):
        impacts.append(impact_for_rule(rid, "added", class_sets, records))
    for rid in diff.get("rules_removed", []):
        imp = impact_for_rule(rid, "removed", class_sets, records)
        # A removed rule may no longer be in the current profiles; flag records
        # that still reference it so they get cleaned up.
        imp["requires_human_review"] = True
        impacts.append(imp)
    for c in diff.get("rules_changed", []):
        rid = c["id"]
        change_types = sorted(c["changes"].keys())
        imp = impact_for_rule(rid, "+".join(change_types), class_sets, records)
        # Force change into MUST is the highest-signal case.
        force = c["changes"].get("force", {})
        if force.get("new") == "MUST" and force.get("old") != "MUST":
            imp["force_escalation_to_must"] = True
            imp["requires_human_review"] = True
        imp["change_detail"] = c["changes"]
        impacts.append(imp)

    # Individual KSI changes -> collectors -> evidence -> SDR node.
    for kid in diff.get("ksis_added", []):
        ksi_impacts.append(impact_for_ksi(kid, "added", ksi_collectors, records))
    for kid in diff.get("ksis_removed", []):
        ksi_impacts.append(impact_for_ksi(kid, "removed", ksi_collectors, records))
    for c in diff.get("ksis_changed", []):
        kid = c["id"]
        change_types = sorted(c["changes"].keys())
        imp = impact_for_ksi(kid, "+".join(change_types), ksi_collectors, records)
        imp["change_detail"] = c["changes"]
        ksi_impacts.append(imp)

    review_needed = [i["rule_id"] for i in impacts if i["requires_human_review"]]
    ksi_review_needed = [i["ksi_id"] for i in ksi_impacts if i["requires_human_review"]]
    return {
        "impact_note": (
            "Downstream impact of upstream FedRAMP changes on this provider's "
            "package. Reading-only; changes nothing and sets no status. FRR "
            "changes map to classes/records/outputs; KSI changes map through the "
            "collector registry to collectors/evidence/SDR node. No FRR->KSI "
            "relationship is invented (the dataset carries none)."),
        "source_summary": diff.get("summary", {}),
        "impacts": impacts,
        "ksi_impacts": ksi_impacts,
        "rules_requiring_review": sorted(review_needed),
        "ksis_requiring_review": sorted(ksi_review_needed),
        "total_requiring_review": len(review_needed) + len(ksi_review_needed),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("old", nargs="?")
    ap.add_argument("new", nargs="?")
    ap.add_argument("--diff", dest="diff_path", default=None,
                    help="use a precomputed dataset_diff JSON instead of old/new")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    if args.diff_path:
        diff = load(args.diff_path)
        if diff is None:
            print(f"Could not read diff at {args.diff_path}")
            return 2
    elif args.old and args.new:
        with open(args.old, encoding="utf-8") as f:
            old = json.load(f)
        with open(args.new, encoding="utf-8") as f:
            new = json.load(f)
        diff = dataset_diff.diff_datasets(old, new)
    else:
        print("Provide OLD NEW datasets or --diff diff.json")
        return 2

    result = compute(diff)
    print(f"Change impact: {result['total_requiring_review']} rule/KSI item(s) "
          "require human review.")
    for imp in result["impacts"]:
        if imp["requires_human_review"]:
            print(f"  {imp['rule_id']} ({imp['change_type']}) -> classes "
                  f"{imp['affected_classes']}, outputs {len(imp['affected_outputs'])}")
    for imp in result.get("ksi_impacts", []):
        if imp["requires_human_review"]:
            print(f"  {imp['ksi_id']} ({imp['change_type']}) -> collectors "
                  f"{len(imp['affected_collectors'])}, outputs {len(imp['affected_outputs'])}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, indent=2)
        print(f"Wrote impact report to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
