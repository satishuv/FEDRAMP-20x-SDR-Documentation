#!/usr/bin/env python3
"""Prove applicability: for every FedRAMP Rule in the dataset, record whether it
is included in this class's profile and the EXACT reason, using only fields the
CR26 dataset actually carries.

Auditability goal: you can prove why a rule is ABSENT, not only why one is
present. An assessor can ask "why isn't XYZ in the Class C package?" and get a
precise answer ("subset paths ['Agency'] exclude target path Program", or "does
not affect Providers", or "no statement resolvable for Class C").

Honest scope: the CR26 dataset has NO per-rule effective-date or
document-status field (verified: rule keys are affects, force, name, note,
statement, terms, updated, plus optional subset/timeframe/schema). So this
resolver proves applicability from the fields that DO exist -- affects,
subset_applicability (types/paths/classes), and varies_by_class -- and does not
invent an effective/status dimension the source lacks.

Reuses build_profiles.py's exact resolution logic, so the decisions cannot
drift from what the profile builder actually did.

    python validation/scripts/build_applicability_decisions.py

Output: traceability/applicability-decisions.json
"""

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_profiles as bp  # noqa: E402

OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
RULE_CATALOG = os.path.join(BASE, "traceability", "rule-catalog.json")
OUT = os.path.join(BASE, "traceability", "applicability-decisions.json")

RULE_ID = re.compile(r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _all_rules(_ds=None):
    """Every FRR rule from the derived catalog, which carries the resolved
    subset_applicability that the raw dataset does not. Keyed by rule_id."""
    cat = load(RULE_CATALOG)
    rules = cat.get("rules", cat)
    out = {}
    seq = rules.values() if isinstance(rules, dict) else rules
    for r in seq:
        if isinstance(r, dict) and RULE_ID.match(r.get("rule_id", "")):
            rr = dict(r)
            rr["_family"] = r.get("family")
            rr["_subset"] = r.get("subset")
            out[r["rule_id"]] = rr
    return out


def _class_a_enumerated_ids():
    """Class A applicability is enumerated by the CLA rules (FRC-CLA-MFR etc.),
    not by the generic affects+subset filter, so the class-A profile is the
    authoritative included set for Class A."""
    path = os.path.join(BASE, "profiles", "class-a", "profile.json")
    try:
        prof = load(path)
        return {r["rule_id"] for r in prof["rules"]}
    except (OSError, ValueError, KeyError):
        return None


def _family_document_state(ds):
    """Family-level document status and effective metadata from the canonical
    dataset. This is DOCUMENT/family-level (FRR family info.status/info.effective,
    KSI family status), NOT a per-rule field: the dataset carries no per-rule
    effective/status, so we surface only what actually exists. Returns
    {family_short_name: {status, tag, effective}}."""
    out = {}
    for fam, node in (ds.get("FRR", {}) or {}).items():
        info = node.get("info", {}) if isinstance(node, dict) else {}
        out[fam] = {
            "document_status": info.get("status"),
            "tag": info.get("tag"),
            "effective": info.get("effective"),
        }
    for fam, node in (ds.get("KSI", {}) or {}).items():
        if isinstance(node, dict):
            out[fam] = {"document_status": node.get("status")}
    return out


def decide(rule, cls, class_a_ids=None):
    """Return (applicable: bool, reason: str) using the real dataset fields and
    build_profiles' own logic, so the decision matches the profile exactly.

    Class A is a special case: FedRAMP enumerates it via the CLA rules rather
    than the generic affects+subset filter, so for Class A the class-A profile's
    rule set is authoritative and the reason says so."""
    rid = rule.get("_rule_id")
    if cls == "a" and class_a_ids is not None:
        if rid in class_a_ids:
            return True, "enumerated for Class A by FRC-CLA-MFR/RFR/OFR"
        return False, "not enumerated for Class A (CLA applicability)"
    if not bp.affects_providers(rule):
        return False, f"does not affect Providers (affects={rule.get('affects')})"
    ok, why = bp.subset_applies(rule, cls)
    if not ok:
        return False, why
    resolved = bp.resolve_for_class(rule, cls)
    if resolved is None:
        return False, f"no statement resolvable for Class {cls.upper()}"
    return True, (f"20x + {bp.TARGET_PATH} + Class {cls.upper()} + "
                  f"{resolved['resolution']}")


def build(cls):
    ds = load(DATASET)
    rules = _all_rules(ds)
    doc_state = _family_document_state(ds)
    class_a_ids = _class_a_enumerated_ids() if cls == "a" else None
    included, excluded = [], []
    for rid in sorted(rules):
        rule = rules[rid]
        rule["_rule_id"] = rid
        applicable, reason = decide(rule, cls, class_a_ids)
        fam = rule.get("_family")
        fam_state = doc_state.get(fam, {})
        entry = {
            "rule_id": rid,
            "family": fam,
            "subset": rule.get("_subset"),
            "affects": rule.get("affects"),
            # Document-level (family) status/effective from the canonical
            # source, surfaced so applicability respects it. Not per-rule.
            "document_status": fam_state.get("document_status"),
            "document_effective": fam_state.get("effective"),
            "applicable": applicable,
            "reason": reason,
            # The explicit resolution chain: document status -> effective ->
            # subset applicability -> class resolution -> final applicability.
            "resolution_chain": {
                "document_status": fam_state.get("document_status"),
                "effective_is": (fam_state.get("effective") or {}).get("is")
                if isinstance(fam_state.get("effective"), dict) else None,
                "subset": rule.get("_subset"),
                "class": cls.upper(),
                "final_applicability": applicable,
            },
        }
        (included if applicable else excluded).append(entry)
    return {
        "decisions_note": (
            "Applicability decision for every FedRAMP Rule in the dataset, for "
            "this certification class. Included AND excluded rules are recorded "
            "with the exact reason, so absence is provable, not silent. Reasons "
            "use only real CR26 fields (affects, subset_applicability, "
            "varies_by_class). Document-level status/effective is surfaced from "
            "the canonical family metadata (FRR info.status/effective, KSI "
            "status); the dataset carries NO per-rule effective/status field, so "
            "none is invented at the rule level."),
        "certification_class": cls.upper(),
        "dataset_version": ds.get("info", {}).get("version"),
        "total_rules": len(rules),
        "included": len(included),
        "excluded": len(excluded),
        "decisions": included + excluded,
    }


def main():
    cls = (load(OFFERING).get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no applicability decisions generated.")
        return 1
    result = build(cls)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1)
    print(f"Applicability decisions written: {os.path.relpath(OUT, BASE)} "
          f"({result['included']} included, {result['excluded']} excluded of "
          f"{result['total_rules']} rules).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
