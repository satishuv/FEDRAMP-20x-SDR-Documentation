# Build rule and KSI catalogs for the FedRAMP 20x SDR framework.
# Reads the canonical CR26 dataset and derives:
#   traceability/rule-catalog.json  - every FRR requirement applicable to 20x, with class B/C/D variants
#   traceability/ksi-catalog.json   - all KSI indicators with statements and control mappings
# Read-only with respect to the dataset. Deterministic. Re-run after every dataset refresh.

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
OUT_DIR = os.path.join(BASE, "traceability")

CLASSES = ("a", "b", "c", "d")


def load_dataset():
    with open(DATASET, encoding="utf-8") as f:
        return json.load(f)


def extract_requirement(req_id, req, family, subset, applicability):
    rec = {
        "rule_id": req_id,
        "family": family,
        "subset": subset,
        "applicability": applicability,
        "name": req.get("name"),
        "force": req.get("force"),
        "statement": req.get("statement"),
        "affects": req.get("affects"),
        "varies_by_class": None,
        "schema": req.get("schema"),
        "reference": req.get("reference"),
    }
    vbc = req.get("varies_by_class")
    if isinstance(vbc, dict):
        variants = {}
        for cls in CLASSES:
            v = vbc.get(cls)
            if isinstance(v, dict):
                variants[cls] = {
                    "statement": v.get("statement"),
                    "force": v.get("force"),
                    "timeframe_type": v.get("timeframe_type"),
                    "timeframe_num": v.get("timeframe_num"),
                }
        rec["varies_by_class"] = variants
    return rec


def subset_applicability(fam_info, subset, branch="all"):
    # subset metadata may live in common info.subsets or in the path-specific
    # info.20x.subsets / info.rev5.subsets blocks. Resolve common PLUS the
    # matching framework-specific block only - a 20x rule must NEVER inherit
    # rev5 subset metadata (and vice versa), per FedRAMP's guidance to resolve
    # common + the matching framework block.
    containers = [fam_info.get("subsets") or {}]
    if branch == "20x":
        containers.append((fam_info.get("20x") or {}).get("subsets") or {})
    elif branch == "rev5":
        containers.append((fam_info.get("rev5") or {}).get("subsets") or {})
    # branch == "all": common only.
    for container in containers:
        meta = container.get(subset)
        if isinstance(meta, dict):
            app = meta.get("applicability") or {}
            return {
                "types": app.get("types"),
                "paths": app.get("paths"),
                "classes": app.get("classes"),
                "affects": app.get("affects"),
            }
    return None


def walk_frr(frr):
    rules = []
    for family, fam_data in frr.items():
        data = fam_data.get("data", {})
        fam_info = fam_data.get("info", {})
        family_name = fam_info.get("name", family)
        for applicability in ("all", "20x"):
            buckets = data.get(applicability)
            if not isinstance(buckets, dict):
                continue
            for subset, reqs in buckets.items():
                if not isinstance(reqs, dict):
                    continue
                sub_app = subset_applicability(fam_info, subset, applicability)
                for req_id, req in reqs.items():
                    if not isinstance(req, dict):
                        continue
                    rec = extract_requirement(req_id, req, family, subset, applicability)
                    rec["family_name"] = family_name
                    rec["subset_applicability"] = sub_app
                    rules.append(rec)
    return rules


def walk_ksi(ksi):
    indicators = []
    for family, fam_data in ksi.items():
        inds = fam_data.get("indicators", {})
        fam_status = fam_data.get("status")
        for ksi_id, ind in inds.items():
            indicators.append(
                {
                    "ksi_id": ksi_id,
                    "family": family,
                    "family_name": fam_data.get("name"),
                    "family_status": fam_status,
                    "name": ind.get("name"),
                    "statement": ind.get("statement"),
                    "controls": ind.get("controls"),
                    # Preserve the official varies_by_class block: the schema
                    # supports per-class KSI statements even if the current
                    # dataset doesn't exercise it heavily. Dropping it would make
                    # the normalizer lossy against the official schema.
                    "varies_by_class": ind.get("varies_by_class"),
                    "status_note": (
                        "empty statement in dataset"
                        if not (ind.get("statement") or ind.get("varies_by_class"))
                        else "ok"
                    ),
                }
            )
    return indicators


def main():
    ds = load_dataset()
    version = ds.get("info", {}).get("version")
    meta = {
        "derived_from": "fedramp-consolidated-rules.json",
        "dataset_version": version,
        # Deterministic: outputs are pinned to the dataset version, never a
        # run timestamp, so an unchanged dataset yields byte-identical output.
        "generated": f"deterministic build from dataset {version}",
        "scope": "FRR requirements applicable to 20x (data.all and data.20x); all KSI indicators",
    }

    rules = walk_frr(ds["FRR"])
    ksis = walk_ksi(ds["KSI"])

    os.makedirs(OUT_DIR, exist_ok=True)
    # newline="\n" on every text writer: without it Windows translates the
    # newlines json.dump emits to CRLF, and the CI regenerate-then-diff gate
    # on Linux can then never match the committed blobs.
    with open(os.path.join(OUT_DIR, "rule-catalog.json"), "w", encoding="utf-8",
              newline="\n") as f:
        json.dump({"meta": meta, "count": len(rules), "rules": rules}, f, indent=1)
    with open(os.path.join(OUT_DIR, "ksi-catalog.json"), "w", encoding="utf-8",
              newline="\n") as f:
        json.dump({"meta": meta, "count": len(ksis), "indicators": ksis}, f, indent=1)

    fams = {}
    for r in rules:
        fams[r["family"]] = fams.get(r["family"], 0) + 1
    print("dataset version:", version)
    print("rules extracted:", len(rules))
    for fam in sorted(fams):
        print(f"  {fam}: {fams[fam]}")
    print("ksi indicators:", len(ksis))
    empty = [k["ksi_id"] for k in ksis if k["status_note"] != "ok"]
    print("ksi with empty statements:", empty)
    return 0


if __name__ == "__main__":
    sys.exit(main())
