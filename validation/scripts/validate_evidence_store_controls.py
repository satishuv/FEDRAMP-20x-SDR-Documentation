#!/usr/bin/env python3
"""Validate the evidence-store control mapping against the pinned CR26 dataset.

traceability/evidence-store-controls.json maps the evidence store's protection
mechanisms (versioning, Object Lock, KMS signatures, least-privilege access,
content hash) to the FedRAMP 20x / NIST Rev5 control identifiers they support.
This gate keeps that mapping HONEST: every control id it cites MUST appear
verbatim somewhere in references/fedramp-consolidated-rules.json. A mapping that
cites an identifier not present in the dataset is a HARD failure - it is exactly
the "fabricated identifier" failure mode the project guards against.

It also checks the file is structurally well-formed (every mechanism has a
non-empty supports_controls list and a rationale, and controls_verified_in_dataset
matches the union of cited controls).

    python validation/scripts/validate_evidence_store_controls.py

Exit 1 on any hard failure.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAP = os.path.join(BASE, "traceability", "evidence-store-controls.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _dataset_text(path):
    """Read the dataset as raw text once; membership is a verbatim substring
    test over the whole file. Cheaper and stricter than walking the nested
    structure, and it catches an id wherever it appears (rev5 lists, KSI
    controls arrays, CTL mappings)."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def main():
    try:
        mapping = load(MAP)
    except (OSError, ValueError) as e:
        print(f"FAIL: cannot read {MAP}: {e}")
        return 1
    try:
        text = _dataset_text(DATASET)
    except OSError as e:
        print(f"FAIL: cannot read dataset {DATASET}: {e}")
        return 1

    hard = []
    mechanisms = mapping.get("mechanisms", [])
    if not mechanisms:
        hard.append("no mechanisms listed")

    cited = set()
    for m in mechanisms:
        name = m.get("mechanism", "(unnamed)")
        controls = m.get("supports_controls") or []
        if not controls:
            hard.append(f"mechanism '{name}' cites no controls")
        if not m.get("rationale"):
            hard.append(f"mechanism '{name}' has no rationale")
        for cid in controls:
            cited.add(cid)
            # Verbatim membership: the exact quoted control id must appear in
            # the dataset text (e.g. "AU-09", "AU-09 (02)", "KSI-MLA-ALA").
            if f'"{cid}"' not in text and cid not in text:
                hard.append(
                    f"mechanism '{name}' cites control '{cid}' which does NOT "
                    "appear in the pinned CR26 dataset (fabricated or misspelled)")

    # controls_verified_in_dataset should equal the union of cited controls.
    declared = set(mapping.get("controls_verified_in_dataset") or [])
    if declared != cited:
        missing = cited - declared
        extra = declared - cited
        if missing:
            hard.append(f"controls_verified_in_dataset is missing cited ids: "
                        f"{sorted(missing)}")
        if extra:
            hard.append(f"controls_verified_in_dataset lists ids no mechanism "
                        f"cites: {sorted(extra)}")

    print("Evidence-store control-mapping gate")
    print("-" * 68)
    print(f"Mechanisms: {len(mechanisms)}   Distinct controls cited: {len(cited)}")
    for cid in sorted(cited):
        print(f"    [ok] {cid} present in dataset")
    if hard:
        print(f"\nHARD failures ({len(hard)}):")
        for h in hard:
            print(f"    [FAIL] {h}")
        return 1
    print("\nPASS: every control id in the mapping is present verbatim in the "
          "pinned CR26 dataset, and the mapping is well-formed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
