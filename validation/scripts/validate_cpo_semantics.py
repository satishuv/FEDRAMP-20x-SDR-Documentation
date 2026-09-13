#!/usr/bin/env python3
"""Semantic completeness validator for the Certification Package Overview.

Schema-valid is not rule-complete. The official CPO JSON schema requires only a
small structural core, but CPO-CSO-OVR requires the CPO to include the
information required by nine referenced rules, and CPO-CSO-MTD requires basic
metadata. This validator - modeled on the SDR semantic validator - derives the
applicable CPO obligations from the pinned dataset and checks the generated CPO
carries a corresponding entry.

Reports two levels, mirroring the trust boundary:
  - MISSING STRUCTURE (the CPO doesn't even carry the required-information map or
    metadata block the generator should always emit): a HARD failure.
  - UNRESOLVED CONTENT (a required item is still TBD): reported. It is a
    submission-preflight blocker, not a build failure, because the public repo
    ships as a template.

    python validation/scripts/validate_cpo_semantics.py

Exit 1 only on missing structure. Unresolved-content counts are informational
here and enforced by preflight.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CPO = os.path.join(BASE, "package", "cpo", "cpo.json")
CPO_MD = os.path.join(BASE, "package", "cpo", "cpo.md")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def _expected_ovr_rules():
    """INDEPENDENTLY derive the CPO-CSO-OVR required-rule set from CR26, so the
    validator does not trust the builder's own items[] list. Returns the set of
    rule ids referenced by CPO-CSO-OVR.following_information, or None if the
    dataset/ rule is unavailable."""
    import re as _re
    ds = load(DATASET)
    if ds is None:
        return None

    def _find(node, target):
        if isinstance(node, dict):
            if target in node:
                return node[target]
            for v in node.values():
                r = _find(v, target)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = _find(v, target)
                if r is not None:
                    return r
        return None

    ovr = _find(ds, "CPO-CSO-OVR") or {}
    ids = set()
    for ref in ovr.get("following_information", []) or []:
        m = _re.search(r"([A-Z]{3}-[A-Z]{3}-[A-Z]{3})", ref)
        if m:
            ids.add(m.group(1))
    return ids or None


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _is_tbd(v):
    return v is None or str(v).strip() == "" or str(v).strip().startswith("TBD")


def main():
    cpo = load(CPO)
    if cpo is None:
        print(f"FAIL: CPO not found at {os.path.relpath(CPO, BASE)}")
        return 1

    hard = []
    unresolved = []

    # Structure: metadata block (CPO-CSO-MTD) must be present.
    mtd = cpo.get("xCpoMetadata")
    if not isinstance(mtd, dict) or mtd.get("cr26_rule") != "CPO-CSO-MTD":
        hard.append("xCpoMetadata (CPO-CSO-MTD) block is missing from the CPO")
    else:
        for f in ("responsible_official", "version", "last_updated", "source_of_update"):
            if _is_tbd(mtd.get(f)):
                unresolved.append(f"CPO metadata {f} is unresolved (CPO-CSO-MTD)")

    # Structure: required-information map (CPO-CSO-OVR) must be present.
    req = cpo.get("xCpoRequiredInformation")
    if not isinstance(req, dict) or not req.get("items"):
        hard.append("xCpoRequiredInformation (CPO-CSO-OVR) map is missing from the CPO")
    else:
        # INDEPENDENTLY derive the expected rule set from CR26 and require exact
        # set equality, so a builder that silently drops a required rule cannot
        # be rubber-stamped by a validator that only reads the builder's own list.
        expected = _expected_ovr_rules()
        actual = {i.get("rule") for i in req["items"]}
        if expected is not None and expected != actual:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            hard.append(f"CPO required-information set does not match the CR26 "
                        f"CPO-CSO-OVR rule set (missing {missing}, extra {extra})")
        for item in req["items"]:
            if _is_tbd(item.get("provider_content")):
                unresolved.append(f"CPO required information for {item.get('rule')} "
                                  f"is unresolved (CPO-CSO-OVR)")

    # Human-readable parity: the .md must exist and mention the metadata + the
    # required-information rules, so JSON and human-readable stay in step.
    parity_gap = []
    if not os.path.isfile(CPO_MD):
        hard.append("CPO human-readable rendering (cpo.md) is missing (CPO-CSO-OVR "
                    "requires both human-readable and JSON formats)")
    else:
        md = open(CPO_MD, encoding="utf-8").read()
        if isinstance(req, dict):
            for item in req.get("items", []):
                rid = item.get("rule", "")
                if rid and rid not in md:
                    parity_gap.append(rid)

    print("CPO semantic completeness")
    print("-" * 68)
    if unresolved:
        print(f"Unresolved content ({len(unresolved)}) - preflight blockers, not build failures:")
        for u in unresolved[:20]:
            print(f"    [content] {u}")
    if parity_gap:
        print(f"Human-readable parity: {len(parity_gap)} required-info rule(s) not "
              f"reflected in cpo.md: {parity_gap[:8]}")
        hard.append(f"{len(parity_gap)} required-information rule(s) present in CPO JSON "
                    "but absent from the human-readable cpo.md (parity gap)")
    if hard:
        print(f"HARD failures ({len(hard)}):")
        for h in hard:
            print(f"    [FAIL] {h}")
        return 1
    print("PASS: CPO carries the CPO-CSO-MTD metadata and CPO-CSO-OVR "
          "required-information map, with human-readable parity. Unresolved "
          "content (if any) is enforced at submission preflight.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
