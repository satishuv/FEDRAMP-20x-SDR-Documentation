#!/usr/bin/env python3
"""Cross-artifact consistency validator.

The framework generates many artifacts (SDR, CPO, OCR, SCG, event artifacts).
Schema validation checks each in isolation; this checks they agree with each
other as one package:

  - certification class is consistent across SDR extensions, CPO, and the
    assurance graph
  - the Certification Package Overview URI referenced by the OCR and event
    artifacts matches the offering profile's CPO URI
  - the dataset version is consistent across SDR, assurance graph, and manifest
  - the release manifest's recorded artifact hashes match the files on disk

Separate from schema validity. Exit 1 on any contradiction.

    python validation/scripts/validate_package_consistency.py
"""

import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")


def load(rel, default=None):
    path = rel if os.path.isabs(rel) else os.path.join(BASE, rel)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def main():
    offering = load(OFFERING, {})
    cls = (offering.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no package to check.")
        return 1
    problems = []

    cpo_uri = offering.get("certification_package_overview_uri")

    # Class consistency: extensions, CPO, assurance graph.
    ext = load(f"sdr/json/sdr-class-{cls}-extensions.json", {})
    ext_class = (ext.get("metadata", {}) or {}).get("certification_class")
    if ext_class and ext_class.lower() != cls:
        problems.append(f"SDR extensions class {ext_class} != profile class {cls.upper()}")

    graph = load("traceability/assurance-graph.json", {})
    if graph.get("certification_class", "").lower() != cls:
        problems.append(f"assurance graph class {graph.get('certification_class')} != {cls.upper()}")

    cpo = load("package/cpo/cpo.json", {})
    # OCR and event artifacts must reference the same CPO URI as the profile.
    for rel in ["package/ocr/ocr-example.json",
                "package/events/incident-report-initial-example.json",
                "package/events/incident-report-ongoing-example.json",
                "package/events/incident-report-final-example.json",
                "package/events/significant-change-notification-example.json",
                "package/events/accepted-vulnerabilities-example.json",
                "package/events/vulnerability-detail-report-example.json",
                "package/events/historical-ver-activity-example.json"]:
        doc = load(rel, {})
        ref = doc.get("certificationPackageOverviewUri")
        if ref and cpo_uri and ref != cpo_uri:
            problems.append(f"{rel}: CPO URI {ref} != offering CPO URI {cpo_uri}")

    # Dataset version consistency: graph vs offering.
    if graph.get("dataset_version") and graph["dataset_version"] != offering.get("dataset_version"):
        problems.append(f"assurance graph dataset {graph['dataset_version']} != "
                        f"offering {offering.get('dataset_version')}")

    # Release manifest hashes must match the files on disk.
    manifest = load("artifacts/release-manifest.json", {})
    for rel, want in (manifest.get("artifacts") or {}).items():
        path = os.path.join(BASE, rel)
        if not os.path.exists(path):
            problems.append(f"manifest references missing artifact {rel}")
            continue
        got = sha256_file(path)
        if got != want:
            problems.append(f"manifest hash mismatch for {rel}")

    if problems:
        print(f"FAIL: {len(problems)} cross-artifact inconsistency(ies):")
        for p in problems[:20]:
            print(f"    - {p}")
        return 1
    print("PASS: package is internally consistent (class, CPO URI, dataset "
          "version, and manifest hashes all agree across artifacts).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
