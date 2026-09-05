# -*- coding: utf-8 -*-
# Build the Rev5-control-to-KSI crosswalk from the canonical dataset's own
# per-KSI controls field. This is the authoritative replacement for pilot-era
# crosswalk spreadsheets that used obsolete KSI identifiers.
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
                    "Rev5 control to 20x KSI crosswalk, generated from the "
                    "canonical dataset's per-KSI controls field. Source of "
                    "truth is FedRAMP's own mapping, not a projection. A "
                    "control absent from this file has no KSI carrying it in "
                    "the current dataset; that does not mean the control "
                    "concept is unaddressed, FedRAMP Rules (FRR) may cover it "
                    "as a process obligation instead."
                ),
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
        w.writerow(["Rev5 Control", "KSI ID", "KSI Name", "KSI Family",
                    "KSI Family Name"])
        for ctrl, entries in ordered.items():
            for e in entries:
                w.writerow([ctrl, e["ksi_id"], e["ksi_name"], e["family"],
                            e["family_name"]])

    print("controls mapped:", len(ordered))
    print("ksis without control mappings:", unmapped_ksis)
    print("outputs:", out_json, "and .csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
