#!/usr/bin/env python3
"""Requirements-differential oracle (HARD-MODE RULE 5 / RULE 6).

INDEPENDENT of the production applicability engine. This walks the RAW pinned
FedRAMP dataset with its own traversal to derive the expected KSI universe and
the Class-B-optional set, then compares against what the production code
(sdr.submitted_ksi_ids / optional_at_class_b_ksis) claims. The two derivations
must reconcile EXACTLY; any discrepancy is a finding and this exits non-zero.

It deliberately does NOT import the production function to compute the expected
set (that would be circular). It parses the dataset structure directly.

    python audit/requirements_oracle.py
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def _find_ksi_indicators(node, out):
    """Independent walk of the REAL dataset shape: KSI.<family>.indicators.<ID>
    where the KSI ID is the LEAF KEY (CR26 nests IDs as keys, not an 'id'
    field). Returns list of (ksi_id, indicator_obj). Does not use the production
    loader."""
    ksi = node.get("KSI") if isinstance(node, dict) else None
    if not isinstance(ksi, dict):
        return
    for fam, famobj in ksi.items():
        if not isinstance(famobj, dict):
            continue
        inds = famobj.get("indicators")
        if not isinstance(inds, dict):
            continue
        for kid, ind in inds.items():
            if isinstance(ind, dict):
                out.append((kid, ind))


def oracle_sets(dataset):
    """Return (all_ksi_ids, optional_at_b) derived independently from raw JSON."""
    inds = []
    _find_ksi_indicators(dataset, inds)
    all_ids, optional_b = set(), set()
    for kid, ind in inds:
        all_ids.add(kid)
        # Independent optional-at-B detection: the class-B statement under
        # varies_by_class carries the Optional marker for KSIs optional at B.
        vbc = ind.get("varies_by_class")
        if isinstance(vbc, dict):
            b = vbc.get("b")
            if isinstance(b, dict):
                stmt = str(b.get("statement", ""))
                if "**Optional:**" in stmt[:40]:
                    optional_b.add(kid)
    return all_ids, optional_b


def main():
    with open(DATASET, encoding="utf-8") as f:
        dataset = json.load(f)
    all_oracle, optional_oracle = oracle_sets(dataset)

    # The derived KSI profile is what the production pipeline ACTUALLY consumes
    # (build_profiles.py generates it from the dataset). Diffing the raw dataset
    # against this derived profile catches source->profile drift independently.
    prof_path = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
    with open(prof_path, encoding="utf-8") as f:
        indicators = json.load(f)["indicators"]
    profile_ids = {k["ksi_id"] for k in indicators}

    # Production side (the thing under test) applied to its own profile.
    sys.path.insert(0, BASE)
    import sdr  # noqa: E402
    prod_all_c = sdr.submitted_ksi_ids(indicators, "c")
    prod_all_b = sdr.submitted_ksi_ids(indicators, "b")
    prod_optional = sdr.optional_at_class_b_ksis(indicators)

    findings = []
    # 1. The derived profile must contain exactly the dataset's KSI universe.
    if profile_ids != all_oracle:
        findings.append(("Derived ksi-profile != dataset KSI universe",
                         {"only_profile": sorted(profile_ids - all_oracle),
                          "only_dataset": sorted(all_oracle - profile_ids)}))
    # 2. Production Class C submits the whole universe.
    if prod_all_c != all_oracle:
        findings.append(("Production Class C != dataset universe",
                         {"only_prod": sorted(prod_all_c - all_oracle),
                          "only_oracle": sorted(all_oracle - prod_all_c)}))
    # 3. Optional-at-B set reconciles (dataset-derived vs production).
    if prod_optional != optional_oracle:
        findings.append(("Class-B-optional set mismatch",
                         {"only_prod": sorted(prod_optional - optional_oracle),
                          "only_oracle": sorted(optional_oracle - prod_optional)}))
    # 4. Class B baseline = universe minus optional (independent arithmetic).
    expected_baseline_b = all_oracle - optional_oracle
    if prod_all_b != expected_baseline_b:
        findings.append(("Class B baseline mismatch",
                         {"only_prod": sorted(prod_all_b - expected_baseline_b),
                          "only_oracle": sorted(expected_baseline_b - prod_all_b)}))

    print("Requirements-differential oracle")
    print("-" * 60)
    print(f"Oracle KSI universe (dataset): {len(all_oracle)}")
    print(f"Oracle optional-at-B: {len(optional_oracle)} {sorted(optional_oracle)}")
    print(f"Derived profile KSIs: {len(profile_ids)}")
    print(f"Production C: {len(prod_all_c)}  B-baseline: {len(prod_all_b)}  "
          f"optional: {len(prod_optional)}")
    if not findings:
        print("\nRECONCILED: dataset == derived profile == production applicability. "
              "EMPTY discrepancy report.")
        return 0
    print(f"\nDISCREPANCIES ({len(findings)}):")
    for name, detail in findings:
        print(f"  [FINDING] {name}: {json.dumps(detail)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
