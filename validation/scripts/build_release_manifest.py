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

FRAMEWORK_VERSION = "1.2.0"


def _sha256_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()


def _source_provenance():
    """Bind the manifest to the exact SOURCE that produced it, not just the
    framework version (multiple commits can report 1.2.0). requirements hashes
    are deterministic file hashes; git commit/tree are read best-effort and are
    stable for a given checkout (so the reproducibility double-build still sees
    a byte-identical manifest). Absent git (e.g. a tarball) they are null."""
    prov = {
        "requirements_sha256": _sha256_file(os.path.join(BASE, "requirements.txt")),
        "requirements_ci_sha256": _sha256_file(os.path.join(BASE, "requirements-ci.txt")),
        "source_commit": None,
        "source_tree": None,
    }
    # A live git commit/tree must NOT be baked into every committed build: the
    # commit hash cannot be known before the commit that contains the manifest
    # (circular), and it would break the CI regenerate-and-diff gate. Record it
    # only when explicitly cutting a release (SDR_RECORD_SOURCE_COMMIT=1), e.g.
    # in the tag/release workflow, where the committed tree is fixed.
    if os.environ.get("SDR_RECORD_SOURCE_COMMIT") == "1":
        import subprocess
        for key, args in (("source_commit", ["rev-parse", "HEAD"]),
                          ("source_tree", ["rev-parse", "HEAD^{tree}"])):
            try:
                out = subprocess.run(["git", "-C", BASE, *args],
                                     capture_output=True, text=True, timeout=10)
                if out.returncode == 0 and out.stdout.strip():
                    prov[key] = out.stdout.strip()
            except Exception:  # noqa: BLE001
                pass
    return prov

# Generated artifacts fingerprinted, per class. Text/JSON only (deterministic).
ARTIFACT_GLOBS = [
    "sdr/json/sdr-class-{c}.json",
    "sdr/json/sdr-class-{c}-extensions.json",
    # The OSCAL export (sdr-class-{c}.oscal.json) is experimental/reference-only
    # and excluded from the customer bundle, so it is NOT fingerprinted here.
    "sdr/human-readable/sdr-class-{c}.txt",
    "package/cpo/cpo.json",
    "package/cpo/cpo.md",
    "package/ocr/ocr-example.json",
    "package/ocr/ocr-example.md",
    "package/scg/secure-configuration-guide.md",
    "package/events/incident-report-initial-example.json",
    "package/events/incident-report-ongoing-example.json",
    "package/events/incident-report-final-example.json",
    "package/events/significant-change-notification-example.json",
    "package/events/significant-change-notification-example.md",
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
    missing = []
    expected = [g.format(c=cls) for g in ARTIFACT_GLOBS]
    # The package-scope manifest is a real customer-facing artifact and must be
    # covered by the cryptographic release manifest too.
    expected.append("package/certification-package-manifest.json")
    for rel in expected:
        path = os.path.join(BASE, rel)
        if os.path.exists(path):
            artifacts[rel] = sha256_file(path)
        else:
            missing.append(rel)
    if missing:
        # A missing EXPECTED artifact must not be silently skipped: the manifest
        # would then attest to an incomplete package. Fail the build.
        raise SystemExit(
            "release manifest: expected artifact(s) missing from the package; "
            "the package is incomplete, refusing to fingerprint it: "
            + ", ".join(missing))

    schemas = {}
    for key, entry in sources.items():
        if key.endswith("_schema"):
            schemas[key] = {
                "version": entry.get("schema_version"),
                "sha256": entry.get("sha256"),
            }

    dataset = sources.get("cr26_consolidated_rules", {})

    # Submission-critical AUTHORITATIVE INPUTS. Some values here (provider
    # verification date, assessment references, availability assertions) affect
    # preflight without necessarily changing a generated artifact, so a signoff
    # bound only to generated outputs could miss a post-signoff input change.
    # Hashing them here folds them into the manifest hash the signoff binds to.
    # The review register is deliberately EXCLUDED to avoid a circular hash.
    input_files = [
        "profiles/common/offering-profile.json",
        "sdr/records/records-store.json",
    ]
    inputs = {}
    for rel in input_files:
        p = os.path.join(BASE, rel)
        if os.path.exists(p):
            inputs[rel] = sha256_file(p)

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
        "inputs": dict(sorted(inputs.items())),
        "artifacts": dict(sorted(artifacts.items())),
        "artifact_count": len(artifacts),
        "release_tag": f"v{FRAMEWORK_VERSION}-cr26-{offering.get('dataset_version')}",
        "source_provenance": _source_provenance(),
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
