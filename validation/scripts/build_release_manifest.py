#!/usr/bin/env python3
"""Build the release manifest: one cryptographic fingerprint of the whole
generated Certification Package.

Records, for the current class, a SHA-256 of every generated artifact plus the
pinned dataset version and hash, the pinned schema versions and hashes, and a
framework version. A reviewer can verify a delivered package matches this
manifest hash-for-hash, and a package can be reconstructed from the recorded
versions.

Deterministic on purpose: no run timestamps, so two builds of unchanged inputs
produce a byte-identical manifest (the reproducibility gate depends on this).
The manifest excludes .docx (its zip container embeds timestamps) and excludes
itself.

    python validation/scripts/build_release_manifest.py

Output: artifacts/release-manifest.json
"""

import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
LOCK = os.path.join(BASE, "references", "sources.lock.json")
OUT = os.path.join(BASE, "artifacts", "release-manifest.json")

FRAMEWORK_VERSION = "1.0.0"

# Generated artifacts fingerprinted, per class. Text/JSON only (deterministic).
ARTIFACT_GLOBS = [
    "sdr/json/sdr-class-{c}.json",
    "sdr/json/sdr-class-{c}-extensions.json",
    "sdr/json/sdr-class-{c}.oscal.json",
    "sdr/human-readable/sdr-class-{c}.txt",
    "package/cpo/cpo.json",
    "package/cpo/cpo.md",
    "package/ocr/ocr-example.json",
    "package/scg/secure-configuration-guide.md",
    "package/events/incident-report-initial-example.json",
    "package/events/incident-report-ongoing-example.json",
    "package/events/incident-report-final-example.json",
    "package/events/significant-change-notification-example.json",
    "package/events/accepted-vulnerabilities-example.json",
    "package/events/vulnerability-detail-report-example.json",
    "package/events/historical-ver-activity-example.json",
    "traceability/assurance-graph.json",
    "traceability/applicability-decisions.json",
    "traceability/rev5-to-20x-crosswalk.csv",
]


def load(path, default=None):
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


def build(cls):
    offering = load(OFFERING, {})
    lock = load(LOCK, {"sources": {}})
    sources = lock.get("sources", {})

    artifacts = {}
    for glob in ARTIFACT_GLOBS:
        rel = glob.format(c=cls)
        path = os.path.join(BASE, rel)
        if os.path.exists(path):
            artifacts[rel] = sha256_file(path)

    schemas = {}
    for key, entry in sources.items():
        if key.endswith("_schema"):
            schemas[key] = {
                "version": entry.get("schema_version"),
                "sha256": entry.get("sha256"),
            }

    dataset = sources.get("cr26_consolidated_rules", {})

    return {
        "manifest_note": (
            "Cryptographic fingerprint of the generated Certification Package. "
            "Deterministic (no run timestamps); a delivered package can be "
            "verified against these hashes and reconstructed from the recorded "
            "versions. This is a build-provenance record, not a compliance "
            "determination."),
        "framework_version": FRAMEWORK_VERSION,
        "certification_class": cls.upper(),
        "dataset_version": offering.get("dataset_version"),
        "dataset_sha256": dataset.get("sha256"),
        "schemas": dict(sorted(schemas.items())),
        "artifacts": dict(sorted(artifacts.items())),
        "artifact_count": len(artifacts),
        "release_tag": f"v{FRAMEWORK_VERSION}-cr26-{offering.get('dataset_version')}",
        "build": {"deterministic": True, "generator": "build_release_manifest.py"},
    }


def main():
    cls = (load(OFFERING, {}).get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no release manifest generated.")
        return 1
    manifest = build(cls)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=1)
    print(f"Release manifest written: {os.path.relpath(OUT, BASE)} "
          f"({manifest['artifact_count']} artifacts, tag {manifest['release_tag']}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
