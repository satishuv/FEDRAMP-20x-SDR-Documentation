#!/usr/bin/env python3
"""Explain one FedRAMP rule or KSI in plain language, grounded in the pinned
dataset and the provider's record store. No fabrication: every fact printed is
read from the canonical dataset (statement, force, family, class applicability)
or from the record the provider actually wrote (status, implementation,
evidence). If a value is not present it says so, rather than inventing text.

    python sdr.py explain FRC-CSO-PKG
    python sdr.py explain KSI-CNA-RNT

This is a usability aid. It never asserts compliance and never sets a status.
"""

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")

RULE_RE = re.compile(r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$")
KSI_RE = re.compile(r"^KSI-[A-Z]{3}-[A-Z]{3}$")


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _rule_maps(ds):
    rules = {}
    for famblock in ds.get("FRR", {}).values():
        for subsets in famblock.get("data", {}).values():
            for items in subsets.values():
                for rid, rule in items.items():
                    if isinstance(rule, dict) and RULE_RE.match(rid):
                        rules[rid] = rule
    fam_frr = {f: ds["FRR"][f].get("info", {}).get("name") for f in ds.get("FRR", {})}
    return rules, fam_frr


def _class_now():
    prof = _load(OFFERING) or {}
    return (prof.get("certification_class") or "b").lower()


def _resolve(rule, cls):
    vbc = rule.get("varies_by_class")
    if vbc and vbc.get(cls) and vbc[cls].get("statement"):
        return vbc[cls]["statement"], vbc[cls].get("force")
    return rule.get("statement"), rule.get("force")


def _explain_rule(rid, cls):
    ds = _load(DATASET)
    if ds is None:
        return f"Cannot read the pinned dataset at {DATASET}."
    rules, fam_frr = _rule_maps(ds)
    rule = rules.get(rid)
    if rule is None:
        return (f"{rid} is not a FedRAMP Rule in the pinned dataset "
                f"({ds.get('info', {}).get('version', 'unknown version')}). "
                "Check the identifier, or try a KSI id like KSI-CNA-RNT.")
    statement, force = _resolve(rule, cls)
    fam = rid.split("-")[0]
    records = _load(RECORDS) or {}
    rec = (records.get("frr") or {}).get(rid, {})
    L = []
    L.append(f"Rule: {rid}  {rule.get('name', '')}".rstrip())
    L.append(f"Family: {fam} ({fam_frr.get(fam, fam)})")
    L.append(f"Force: {force or 'stated in rule text'}  "
             f"(MUST is mandatory, SHOULD is expected, MAY is optional)")
    L.append(f"Applies at: Class {cls.upper()} (current offering profile)")
    L.append("")
    L.append("What FedRAMP requires (verbatim from the dataset):")
    L.append(f"  {statement or 'No statement resolvable for this class.'}")
    L.append("")
    L.append("How this record addresses it:")
    L.append(f"  Status: {rec.get('implementation_status', 'Not Implemented')}")
    for s in rec.get("implementation", []) or []:
        L.append(f"  Implementation: {s}")
    for s in rec.get("validation", []) or []:
        L.append(f"  Validation: {s}")
    ext = rec.get("extension", {})
    if ext.get("independent_verification"):
        L.append(f"  Independent verification: {ext['independent_verification']}")
    arts = ext.get("rule_artifacts", []) if ext else []
    L.append(f"  Rule-specific artifacts: "
             f"{'; '.join(str(a) for a in arts) if arts else 'None recorded'}")
    L.append("")
    L.append("This summary is generated from the dataset and your record store. "
             "It is not a compliance determination; a human owns that.")
    return "\n".join(L)


def _explain_ksi(kid, cls):
    prof = _load(KSI_PROFILE) or {}
    inds = {k["ksi_id"]: k for k in prof.get("indicators", [])}
    k = inds.get(kid)
    if k is None:
        return (f"{kid} is not a KSI in the pinned KSI profile. "
                "Check the identifier (families: CED CMT CNA IAM INR MLA PIY "
                "RPL SCR SVC).")
    records = _load(RECORDS) or {}
    rec = (records.get("ksi") or {}).get(kid, {})
    L = []
    L.append(f"KSI: {kid}  {k.get('name', '')}".rstrip())
    L.append(f"Family: {k.get('family')} ({k.get('family_name')})")
    mam = k.get("minimum_automated_methods", {}).get(f"class_{cls}")
    L.append(f"Minimum automated methods at Class {cls.upper()}: {mam} "
             "(FRC-CSX-VVK: MAY at A, SHOULD at B, MUST at C and D)")
    L.append("")
    L.append("Security outcome (verbatim from the dataset):")
    L.append(f"  {k.get('statement') or 'FedRAMP pending: no statement yet.'}")
    L.append("")
    L.append("How this record addresses it:")
    L.append(f"  Status: {rec.get('implementation_status', 'Not Implemented')}")
    for s in rec.get("implementation", []) or []:
        L.append(f"  Implementation: {s}")
    tests = rec.get("tests", []) or []
    L.append(f"  Tests: {'; '.join(tests) if tests else 'None defined yet'}")
    ev = rec.get("evidence", []) or []
    L.append(f"  Evidence entries: {len(ev)}")
    for e in ev[:3]:
        loc = e.get("evidenceLocation", "?")
        h = e.get("xEvidenceContentHash", "")
        L.append(f"    - {e.get('evidenceType', '?')}: {loc}"
                 + (f"  [{h}]" if h else ""))
    L.append("")
    L.append("This summary is generated from the dataset and your record store. "
             "It is not a compliance determination; a human owns that.")
    return "\n".join(L)


def explain(identifier, cls=None):
    cls = (cls or _class_now()).lower()
    ident = identifier.strip().upper()
    if KSI_RE.match(ident):
        return _explain_ksi(ident, cls)
    if RULE_RE.match(ident):
        return _explain_rule(ident, cls)
    return (f"'{identifier}' does not look like a FedRAMP Rule id "
            "(e.g. FRC-CSO-PKG) or a KSI id (e.g. KSI-CNA-RNT).")


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python sdr.py explain <RULE-ID or KSI-ID>")
        return 2
    print(explain(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
