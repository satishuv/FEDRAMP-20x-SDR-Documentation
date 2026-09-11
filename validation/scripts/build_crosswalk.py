# -*- coding: utf-8 -*-
# Build the NIST-control-to-KSI reverse index from the canonical dataset's own
# per-KSI controls field. This is the authoritative derivation of the
# FedRAMP-declared related-control relationships, replacing pilot-era crosswalk
# spreadsheets that used obsolete KSI identifiers.
#
# This is a RELATED-CONTROL reverse index, not a statement of equivalence. A
# control appearing against a KSI means the CR26 dataset lists it as a related
# control for that indicator; it does NOT mean implementing the KSI satisfies
# the NIST control, nor the reverse. Relationships come only from the dataset,
# never from repository keyword matching or analytical enrichment.
#
# Outputs:
#   traceability/rev5-to-20x-crosswalk.json   control -> KSIs (reverse view)
#   traceability/rev5-to-20x-crosswalk.csv    same, flat, for Excel users
#
# Pipeline position: run after build_catalogs.py.

import csv
import json
import os
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KSI_CATALOG = os.path.join(BASE, "traceability", "ksi-catalog.json")
FAMILY_NAMES = os.path.join(BASE, "traceability", "family-names.json")

# NIST catalog release the control identifiers are read against. Pinned so a
# cold reader knows exactly which release the IDs correspond to, mirroring how
# the CR26 dataset is pinned. See references/sources.lock.json. Release 5.2.0
# (2025-08-27) is the current SP 800-53 Rev. 5 patch release.
NIST_CATALOG = "NIST SP 800-53 Rev. 5"
NIST_RELEASE = "5.2.0"
NIST_RELEASE_DATE = "2025-08-27"


def main():
    with open(KSI_CATALOG, encoding="utf-8") as f:
        ksis = json.load(f)["indicators"]
    with open(FAMILY_NAMES, encoding="utf-8") as f:
        fam_names = json.load(f)

    control_map = defaultdict(list)
    unmapped_ksis = []
    for k in ksis:
        controls = k.get("controls") or []
        if not controls:
            unmapped_ksis.append(k["ksi_id"])
        for c in controls:
            control_map[c.upper()].append(
                {
                    "ksi_id": k["ksi_id"],
                    "ksi_name": k["name"],
                    "family": k["family"],
                    "family_name": k["family_name"],
                }
            )

    def sort_key(ctrl):
        fam, _, rest = ctrl.partition("-")
        num = rest.split(".")[0]
        enh = rest.split(".")[1] if "." in rest else "0"
        return (fam, int(num) if num.isdigit() else 0,
                int(enh) if enh.isdigit() else 0)

    ordered = dict(sorted(control_map.items(), key=lambda kv: sort_key(kv[0])))

    out_json = os.path.join(BASE, "traceability", "rev5-to-20x-crosswalk.json")
    with open(out_json, "w", encoding="utf-8", newline="\n") as f:
        json.dump(
            {
                "note": (
                    "NIST control to 20x KSI reverse index, generated from the "
                    "canonical dataset's per-KSI controls field. Source of "
                    "truth is FedRAMP's own related-control mapping, not a "
                    "projection. A control absent from this file has no KSI "
                    "carrying it in the current dataset; that does not mean the "
                    "control concept is unaddressed, FedRAMP Rules (FRR) may "
                    "cover it as a process obligation instead."
                ),
                "relationship": "fedramp_declared_related_control",
                "direction": "nist_control -> ksis",
                "equivalence": False,
                "equivalence_note": (
                    "This is relatedness, not equivalence. A control listed "
                    "against a KSI does not mean the KSI satisfies the NIST "
                    "control or the reverse. Do not read these rows as control "
                    "satisfaction."
                ),
                "nist_catalog": NIST_CATALOG,
                "nist_release": NIST_RELEASE,
                "nist_release_date": NIST_RELEASE_DATE,
                "relationship_source": "CR26 dataset (ksi-catalog.json controls field)",
                "dataset_note": "Derived from ksi-catalog.json at build time.",
                "controls_mapped": len(ordered),
                "ksis_without_control_mappings": unmapped_ksis,
                "crosswalk": ordered,
            },
            f, indent=1,
        )

    out_csv = os.path.join(BASE, "traceability", "rev5-to-20x-crosswalk.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["NIST Control (source)", "NIST Catalog", "NIST Release",
                    "Relationship", "Equivalence", "KSI ID", "KSI Name",
                    "KSI Family", "KSI Family Name"])
        for ctrl, entries in ordered.items():
            for e in entries:
                w.writerow([ctrl, NIST_CATALOG, NIST_RELEASE,
                            "fedramp_declared_related_control", "false",
                            e["ksi_id"], e["ksi_name"], e["family"],
                            e["family_name"]])

    print("controls mapped:", len(ordered))
    print("ksis without control mappings:", unmapped_ksis)
    print("outputs:", out_json, "and .csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
