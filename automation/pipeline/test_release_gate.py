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
    # Active-class bundle: the publish path assembles the bundle from exactly
    # what the release manifest fingerprints (active class only), not from
    # all-class wildcards. Assert the buildspec publishes the assembled bundle
    # and runs the assembler.
    files, _excludes = _bundle_globs(buildspec)
    check("buildspec publishes the assembled active-class bundle",
          any("release-bundle" in g for g in files))
    check("buildspec does NOT publish all-class SDR wildcards",
          not any(g.startswith("sdr/json/**") or g.startswith("sdr/human-readable/**")
                  for g in files))
    check("buildspec runs the bundle assembler",
          "assemble_release_bundle.py" in buildspec)

    # Run the assembler and verify its output is manifest-complete and contains
    # no inactive-class SDR. This makes bundle<->manifest drift and inactive-class
    # leakage a test failure, not a silent inconsistency the customer discovers.
    import importlib.util
    spec_ab = importlib.util.spec_from_file_location(
        "arb", os.path.join(BASE, "validation", "scripts", "assemble_release_bundle.py"))
    arb = importlib.util.module_from_spec(spec_ab); spec_ab.loader.exec_module(arb)
    res = arb.assemble()
    manifest = json.load(open(MANIFEST, encoding="utf-8")) if os.path.exists(MANIFEST) else {}
    active = (manifest.get("certification_class") or "").lower()
    fingerprinted = sorted((manifest.get("artifacts") or {}).keys())
    copied = set(res["copied"]) if res else set()
    check("assembled bundle contains every fingerprinted artifact "
          + (f"(missing: {[p for p in fingerprinted if p not in copied][:5]})"
             if res and any(p not in copied for p in fingerprinted) else ""),
          bool(res) and not res["missing"] and all(p in copied for p in fingerprinted))
    stray = [p for p in copied if p.startswith("sdr/") and f"sdr-class-{active}" not in p]
    check("assembled bundle contains NO inactive-class SDR"
          + (f" (stray: {stray[:3]})" if stray else ""),
          not stray)
    check("the SBOM is in the assembled bundle",
          "artifacts/sbom.cdx.json" in copied)

    # The attestation must bind the manifest by hash and must NOT be produced by
    # mutating the manifest (the manifest's own source_commit stays null so a
    # signoff bound to its hash survives).
    spec = importlib.util.spec_from_file_location(
        "bra", os.path.join(BASE, "validation", "scripts", "build_release_attestation.py"))
    bra = importlib.util.module_from_spec(spec); spec.loader.exec_module(bra)
    att = bra.build_attestation()
    import hashlib
    manifest_sha = ("sha256:" + hashlib.sha256(open(MANIFEST, "rb").read()).hexdigest()
                    if os.path.exists(MANIFEST) else None)
    check("attestation binds the current manifest hash",
          att and att.get("release_manifest_sha256") == manifest_sha)
    check("attestation records real git provenance (commit non-null)",
          bool(att and att.get("source_commit")))
    check("attestation records real git provenance (tree non-null)",
          bool(att and att.get("source_tree")))
    check("attestation git_available is True",
          bool(att and att.get("git_available")))
    # Fail-closed contract: main() must refuse (non-zero) when provenance is
    # unavailable, rather than writing a null-provenance attestation and
    # exiting 0. Verify by forcing _git() to return None so git_available=False.
    _orig_git = bra._git
    try:
        bra._git = lambda *a, **k: None
        rc_no_prov = bra.main()
    finally:
        bra._git = _orig_git
    check("attestation main() fails closed when git provenance is unavailable",
          rc_no_prov != 0)
    check("manifest source_commit stays null (not mutated by release)",
          (manifest.get("source_provenance", {}) or {}).get("source_commit") is None)

    print(f"\n{passed}/{passed + failed} release-gate checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
