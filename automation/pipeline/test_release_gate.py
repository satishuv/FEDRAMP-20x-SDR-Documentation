#!/usr/bin/env python3
"""Assert the publication pipeline hard-gates submission readiness.

The publish path is Validate -> Collect -> Human Approval -> Publish. The
validate buildspec only hard-gates package-preflight when RELEASE_MODE=true, so
the deployed ValidateProject MUST set it - otherwise a package with known
readiness blockers could reach Publish. This test parses the CloudFormation
template textually (no yaml dependency; CFN short tags are not plain YAML) and
confirms the wiring.

    python automation/pipeline/test_release_gate.py
"""

import os
import re
import sys
import json
import fnmatch

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.join(HERE, "sdr-pipeline.yaml")
BUILDSPEC = os.path.join(HERE, "buildspec-validate.yml")
BASE = os.path.dirname(os.path.dirname(HERE))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")


def _bundle_globs(buildspec):
    """Extract the artifacts.files globs and exclude-paths from the buildspec."""
    files, excludes, section = [], [], None
    for line in buildspec.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue  # comments and blanks never open, close, or fill a section
        if s.startswith("files:"):
            section = "files"; continue
        if s.startswith("exclude-paths:"):
            section = "exclude"; continue
        if s.startswith("- "):
            if section:
                item = s[2:].strip().strip('"')
                (files if section == "files" else excludes).append(item)
            continue
        # A real (non-comment) key line at this or a lower indent closes the list.
        section = None
    return files, excludes


def _covered(path, globs):
    """True if path is matched by any bundle glob. Handles exact paths,
    'dir/**/*' recursive trees, 'dir/**/*.ext' recursive-with-suffix,
    'dir/name.*' suffix globs, and plain fnmatch."""
    for g in globs:
        if g == path:
            return True
        if g.endswith("/**/*"):
            prefix = g[:-len("/**/*")]
            if path == prefix or path.startswith(prefix + "/"):
                return True
        elif "/**/*." in g:
            # recursive tree restricted to a suffix, e.g. sdr/json/**/*.oscal.json
            prefix, suffix = g.split("/**/*.", 1)
            if path.startswith(prefix + "/") and path.endswith("." + suffix):
                return True
        elif "**" in g:
            pat = g.replace("/**/", "/").replace("**/", "").replace("/**", "")
            if fnmatch.fnmatch(path, pat):
                return True
        elif fnmatch.fnmatch(path, g):
            return True
    return False


def main():
    pipeline = open(PIPELINE, encoding="utf-8").read()
    buildspec = open(BUILDSPEC, encoding="utf-8").read()
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    # The buildspec must run package-preflight and hard-gate it under RELEASE_MODE.
    check("buildspec runs package-preflight",
          "package-preflight" in buildspec)
    check("buildspec hard-gates when RELEASE_MODE=true",
          re.search(r'RELEASE_MODE.*=.*true', buildspec) is not None
          and "exit 1" in buildspec)

    # The ValidateProject in the publish pipeline must set RELEASE_MODE=true.
    vp = pipeline.split("ValidateProject:", 1)[-1].split("DriftCheckProject:", 1)[0]
    check("publish pipeline ValidateProject sets RELEASE_MODE",
          "RELEASE_MODE" in vp)
    check("ValidateProject RELEASE_MODE value is true",
          re.search(r'RELEASE_MODE[\s\S]{0,120}?"true"', vp) is not None
          or re.search(r'RELEASE_MODE[\s\S]{0,120}?true', vp) is not None)

    # Bundle-vs-manifest parity: every artifact the release manifest fingerprints
    # for delivery must be covered by the publication bundle globs (and not
    # excluded). This makes the SBOM-missing-from-bundle class of drift a test
    # failure rather than a silent inconsistency the customer discovers.
    files, excludes = _bundle_globs(buildspec)
    manifest = json.load(open(MANIFEST, encoding="utf-8")) if os.path.exists(MANIFEST) else {}
    fingerprinted = []
    arts = manifest.get("artifacts") or manifest.get("artifact_hashes") or {}
    if isinstance(arts, dict):
        fingerprinted = list(arts.keys())
    elif isinstance(arts, list):
        fingerprinted = [a.get("path") for a in arts if isinstance(a, dict) and a.get("path")]
    # Delivery-intended = fingerprinted, not an OSCAL reference export, not a docx.
    delivery = [p for p in fingerprinted
                if p and not p.endswith(".oscal.json") and not p.endswith(".docx")]
    missing = [p for p in delivery
               if not _covered(p, files) or _covered(p, excludes)]
    check("every delivery-intended fingerprinted artifact is in the publish bundle "
          + (f"(missing: {missing[:5]})" if missing else ""),
          not missing)
    check("the SBOM specifically is in the publish bundle",
          _covered("artifacts/sbom.cdx.json", files))

    print(f"\n{passed}/{passed + failed} release-gate checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
