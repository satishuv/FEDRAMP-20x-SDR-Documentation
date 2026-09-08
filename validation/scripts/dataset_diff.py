#!/usr/bin/env python3
"""Diff two FedRAMP Consolidated Rules datasets and report what materially moved.

Reports rules added/removed, and for surviving rules any change in force level
(MAY/SHOULD/MUST/...), applicability branch (all/20x/rev5), or statement text;
plus KSI count and per-family changes. Reporting tool, not a gate: always exits 0.

Wire into the drift workflow after a dataset bump: run
  python validation/scripts/dataset_diff.py <old.json> <new.json> --json diff.json
and attach the summary to the review PR the drift-check opens.

Dataset structure (confirmed against references/fedramp-consolidated-rules.json):
top-level FRR[process]['data'][applicability in {all,20x,rev5}][subset][RULE-ID],
each rule a dict with 'force' and 'statement'. KSIs live under top-level
KSI[family]. The walker is defensive: it keys rules by their ID wherever it
finds a dict carrying 'force'/'statement', and records the applicability branch
seen on the path.

Usage:
  python validation/scripts/dataset_diff.py OLD.json NEW.json [--json OUT.json]
"""

import argparse
import json
import re
import sys

RULE_ID = re.compile(r"^[A-Z]{2,4}-[A-Z]{2,4}-[A-Z]{2,4}$")
APPLICABILITIES = {"all", "20x", "rev5"}


def _index_rules(dataset):
    """Return {rule_id: {'force','statement','applicability'}} from a dataset.
    Walks FRR defensively; applicability is the nearest all/20x/rev5 ancestor."""
    frr = dataset.get("FRR", {})
    out = {}

    def walk(node, applic=None):
        if not isinstance(node, dict):
            return
        for key, val in node.items():
            next_applic = key if key in APPLICABILITIES else applic
            if isinstance(val, dict) and ("force" in val or "statement" in val) \
                    and RULE_ID.match(key or ""):
                out[key] = {
                    "force": val.get("force"),
                    "statement": val.get("statement"),
                    "applicability": next_applic,
                }
            walk(val, next_applic)

    walk(frr)
    return out


def _index_ksis(dataset):
    """Return {family: count_of_indicators} and total."""
    ksi = dataset.get("KSI", {})
    per_family = {}
    total = 0
    for fam, body in ksi.items():
        inds = body.get("indicators", body) if isinstance(body, dict) else {}
        # indicators may be nested under 'indicators' or be the dict itself;
        # count keys that look like KSI ids.
        count = sum(1 for k in inds if re.match(r"^KSI-", k)) if isinstance(inds, dict) else 0
        if count == 0 and isinstance(body, dict):
            count = sum(1 for k in body if re.match(r"^KSI-", k))
        per_family[fam] = count
        total += count
    return per_family, total


def diff_datasets(old, new):
    old_rules = _index_rules(old)
    new_rules = _index_rules(new)
    old_ids = set(old_rules)
    new_ids = set(new_rules)

    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)

    changed = []
    for rid in sorted(old_ids & new_ids):
        o, n = old_rules[rid], new_rules[rid]
        deltas = {}
        if o["force"] != n["force"]:
            deltas["force"] = {"old": o["force"], "new": n["force"]}
        if o["applicability"] != n["applicability"]:
            deltas["applicability"] = {"old": o["applicability"],
                                       "new": n["applicability"]}
        if (o["statement"] or "") != (n["statement"] or ""):
            deltas["statement"] = {"old": o["statement"], "new": n["statement"]}
        if deltas:
            changed.append({"id": rid, "changes": deltas})

    old_fam, old_total = _index_ksis(old)
    new_fam, new_total = _index_ksis(new)
    ksi_family_changes = {
        fam: {"old": old_fam.get(fam, 0), "new": new_fam.get(fam, 0)}
        for fam in set(old_fam) | set(new_fam)
        if old_fam.get(fam, 0) != new_fam.get(fam, 0)
    }

    return {
        "rules_added": added,
        "rules_removed": removed,
        "rules_changed": changed,
        "ksi_total": {"old": old_total, "new": new_total},
        "ksi_family_changes": ksi_family_changes,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "force_changes": sum(1 for c in changed if "force" in c["changes"]),
        },
    }


def render(d):
    lines = []
    s = d["summary"]
    lines.append(f"Rules: +{s['added']} added, -{s['removed']} removed, "
                 f"{s['changed']} changed ({s['force_changes']} force changes).")
    if d["ksi_total"]["old"] != d["ksi_total"]["new"]:
        lines.append(f"KSI total: {d['ksi_total']['old']} -> {d['ksi_total']['new']}")
    for rid in d["rules_added"]:
        lines.append(f"  + {rid}")
    for rid in d["rules_removed"]:
        lines.append(f"  - {rid}")
    for c in d["rules_changed"]:
        for field, delta in c["changes"].items():
            if field == "statement":
                lines.append(f"  ~ {c['id']} statement changed")
            else:
                lines.append(f"  ~ {c['id']} {field}: {delta['old']} -> {delta['new']}")
    for fam, delta in sorted(d["ksi_family_changes"].items()):
        lines.append(f"  ~ KSI {fam}: {delta['old']} -> {delta['new']}")
    if not (d["rules_added"] or d["rules_removed"] or d["rules_changed"]
            or d["ksi_family_changes"]):
        lines.append("  No material changes detected.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    with open(args.old, encoding="utf-8") as f:
        old = json.load(f)
    with open(args.new, encoding="utf-8") as f:
        new = json.load(f)

    result = diff_datasets(old, new)
    print(render(result))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, indent=2)
        print(f"\nWrote machine-readable diff to {args.json_out}")
    return 0  # reporting tool, never a gate


if __name__ == "__main__":
    sys.exit(main())
