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
            if isinstance(val, dict) and (
                    "force" in val or "statement" in val or "varies_by_class" in val) \
                    and RULE_ID.match(key or ""):
                out[key] = {
                    "force": val.get("force"),
                    "statement": val.get("statement"),
                    "applicability": next_applic,
                    # Structured semantics that can change without touching the
                    # statement text. CR26 2026.09.13.02 added timeframe ranges
                    # and top-level timing to several rules; a diff that ignores
                    # these silently under-reports a material rule change.
                    "timeframe": {
                        t: val.get(t) for t in
                        ("timeframe_type", "timeframe_num",
                         "timeframe_num_min", "timeframe_num_max")
                        if t in val
                    },
                    "artifacts": val.get("artifacts"),
                    "following_information": val.get("following_information"),
                    "varies_by_class": val.get("varies_by_class"),
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


def _index_ksi_detail(dataset):
    """Return {ksi_id: {statement, controls}} for individual-KSI change
    detection. Statement text and related NIST controls are what materially
    change; counts alone hide a reworded or re-mapped indicator."""
    out = {}
    ksi = dataset.get("KSI", {})
    for fam, body in ksi.items():
        if not isinstance(body, dict):
            continue
        inds = body.get("indicators", body)
        if not isinstance(inds, dict):
            continue
        for kid, entry in inds.items():
            if not re.match(r"^KSI-", kid) or not isinstance(entry, dict):
                continue
            out[kid] = {
                "statement": entry.get("statement") or entry.get("text"),
                "controls": entry.get("controls") or entry.get("nist_controls") or [],
            }
    return out


def _index_definitions(dataset):
    """Return {FRD-id: definition-text} from the FRD section. Walks defensively
    since definitions may nest; a leaf is a dict carrying 'definition'."""
    out = {}
    frd = dataset.get("FRD", {})

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and "definition" in v:
                    out[k] = v.get("definition")
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(frd)
    return out


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
        if o.get("timeframe") != n.get("timeframe"):
            deltas["timeframe"] = {"old": o.get("timeframe"),
                                   "new": n.get("timeframe")}
        if o.get("artifacts") != n.get("artifacts"):
            deltas["artifacts"] = {"old": o.get("artifacts"),
                                   "new": n.get("artifacts")}
        if o.get("following_information") != n.get("following_information"):
            deltas["following_information"] = {
                "old": o.get("following_information"),
                "new": n.get("following_information")}
        if o.get("varies_by_class") != n.get("varies_by_class"):
            deltas["varies_by_class"] = {"old": o.get("varies_by_class"),
                                         "new": n.get("varies_by_class")}
        if deltas:
            changed.append({"id": rid, "changes": deltas})

    old_fam, old_total = _index_ksis(old)
    new_fam, new_total = _index_ksis(new)
    ksi_family_changes = {
        fam: {"old": old_fam.get(fam, 0), "new": new_fam.get(fam, 0)}
        for fam in set(old_fam) | set(new_fam)
        if old_fam.get(fam, 0) != new_fam.get(fam, 0)
    }

    # Individual KSI changes (statement/controls), not merely count deltas.
    old_ksi = _index_ksi_detail(old)
    new_ksi = _index_ksi_detail(new)
    ksis_added = sorted(set(new_ksi) - set(old_ksi))
    ksis_removed = sorted(set(old_ksi) - set(new_ksi))
    ksis_changed = []
    for kid in sorted(set(old_ksi) & set(new_ksi)):
        o, n = old_ksi[kid], new_ksi[kid]
        kd = {}
        if (o.get("statement") or "") != (n.get("statement") or ""):
            kd["statement"] = {"old": o.get("statement"), "new": n.get("statement")}
        if (o.get("controls") or []) != (n.get("controls") or []):
            kd["controls"] = {"old": o.get("controls"), "new": n.get("controls")}
        if kd:
            ksis_changed.append({"id": kid, "changes": kd})

    # FRD (controlled definitions) add/remove/change. CR26 2026.09.13.02 added
    # the force-of-rule definitions (FRD-MAY/MST/MNT/SHD/SNT); a definition
    # change can shift the meaning of every rule that uses the term, so it is a
    # material delta the engine must surface.
    old_defs = _index_definitions(old)
    new_defs = _index_definitions(new)
    defs_added = sorted(set(new_defs) - set(old_defs))
    defs_removed = sorted(set(old_defs) - set(new_defs))
    defs_changed = sorted(k for k in set(old_defs) & set(new_defs)
                          if old_defs[k] != new_defs[k])

    return {
        "rules_added": added,
        "rules_removed": removed,
        "rules_changed": changed,
        "ksi_total": {"old": old_total, "new": new_total},
        "ksi_family_changes": ksi_family_changes,
        "ksis_added": ksis_added,
        "ksis_removed": ksis_removed,
        "ksis_changed": ksis_changed,
        "definitions_added": defs_added,
        "definitions_removed": defs_removed,
        "definitions_changed": defs_changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "force_changes": sum(1 for c in changed if "force" in c["changes"]),
            "timeframe_changes": sum(1 for c in changed if "timeframe" in c["changes"]),
            "ksis_added": len(ksis_added),
            "ksis_removed": len(ksis_removed),
            "ksis_changed": len(ksis_changed),
            "definitions_added": len(defs_added),
            "definitions_removed": len(defs_removed),
            "definitions_changed": len(defs_changed),
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
    # Individual KSI changes (statement/controls), not just family counts.
    for kid in d.get("ksis_added", []):
        lines.append(f"  + KSI {kid}")
    for kid in d.get("ksis_removed", []):
        lines.append(f"  - KSI {kid}")
    for c in d.get("ksis_changed", []):
        lines.append(f"  ~ KSI {c['id']} {'/'.join(sorted(c['changes']))} changed")
    # Controlled FedRAMP definitions (FRD): a definition change can shift the
    # meaning of every rule that uses the term (e.g. MUST/SHOULD/MAY).
    for fid in d.get("definitions_added", []):
        lines.append(f"  + definition {fid}")
    for fid in d.get("definitions_removed", []):
        lines.append(f"  - definition {fid}")
    for fid in d.get("definitions_changed", []):
        lines.append(f"  ~ definition {fid} changed")
    if not (d["rules_added"] or d["rules_removed"] or d["rules_changed"]
            or d["ksi_family_changes"] or d.get("ksis_added") or d.get("ksis_removed")
            or d.get("ksis_changed") or d.get("definitions_added")
            or d.get("definitions_removed") or d.get("definitions_changed")):
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
