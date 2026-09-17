#!/usr/bin/env python3
"""Emit artifacts/release-attestation.json: a release-time envelope that binds
the DETERMINISTIC release manifest to the exact git source that produced it,
WITHOUT mutating the manifest.

Why a separate file rather than stamping the manifest:
  - The human package signoff (checked by package-preflight) is bound to the
    SHA-256 of release-manifest.json's bytes. If a release step added git
    commit/tree INTO that manifest, its hash would change and the prior signoff
    would silently go stale.
  - The commit hash also cannot be known before the commit that contains the
    manifest (circular), and mutating the manifest breaks the CI
    regenerate-and-diff gate.

So the ordering is: build -> validate -> reproducibility -> human signoff (binds
the deterministic manifest) -> package-preflight (verifies that binding) ->
THIS attestation (binds that same manifest hash to the git commit/tree) -> tag.
The attestation references the manifest by hash; it never changes it.

This file is NOT committed in ordinary builds (it names a specific commit and is
release-only); it is produced at release/publish time. Run:

    python validation/scripts/build_release_attestation.py
"""

import hashlib
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")
ATTESTATION = os.path.join(BASE, "artifacts", "release-attestation.json")


def _git(*args):
    try:
        r = subprocess.run(["git", "-C", BASE, *args],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return None


def build_attestation():
    if not os.path.exists(MANIFEST):
        print("FAIL. No release-manifest.json; run the build first.")
        return None
    raw = open(MANIFEST, "rb").read()
    manifest_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    manifest = json.loads(raw)
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    attestation = {
        "attestation_note": (
            "Binds the deterministic release-manifest.json (by SHA-256) to the "
            "exact git source that produced it. This file is release-only and "
            "does not modify the manifest, so a human signoff bound to the "
            "manifest hash stays valid. Not a compliance determination."),
        "release_tag": manifest.get("release_tag"),
        "framework_version": manifest.get("framework_version"),
        "dataset_version": manifest.get("dataset_version"),
        "release_manifest_sha256": manifest_sha,
        "source_commit": commit,
        "source_tree": tree,
        "git_available": bool(commit and tree),
    }
    return attestation


def main():
    att = build_attestation()
    if att is None:
        return 1
    # Fail-closed: a release attestation whose whole purpose is to bind the
    # manifest to the exact git source is meaningless without that source. If
    # the commit/tree cannot be resolved, do NOT write a hollow attestation with
    # null provenance and exit 0 - that would let sdr.py release and the
    # RELEASE_MODE publish path treat a provenance-less package as releasable.
    # Refuse instead, consistent with the repo's fail-closed philosophy.
    if not att["git_available"]:
        print("FAIL. git commit/tree unavailable (not a git checkout or git "
              "not on PATH); cannot bind the manifest to a source commit. A "
              "release attestation requires real provenance - refusing to "
              "write a null-provenance attestation. Run from a full git "
              "checkout (the CodePipeline source uses CODEBUILD_CLONE_REF so "
              "the .git metadata is present).")
        return 1
    with open(ATTESTATION, "w", encoding="utf-8", newline="\n") as f:
        json.dump(att, f, indent=1)
        f.write("\n")
    print(f"Release attestation written: {os.path.relpath(ATTESTATION, BASE)}")
    print(f"  manifest sha256 {att['release_manifest_sha256']}")
    print(f"  source commit   {att['source_commit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
