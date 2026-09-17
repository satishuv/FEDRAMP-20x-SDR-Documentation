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

    # Release-path parity: a RELEASE_MODE build must run the SAME full gate the
    # GitHub/local release runs - the offline test suite (full `sdr.py validate`,
    # NOT `validate --no-tests`) AND a double-build reproducibility check - so
    # the AWS release path is not weaker than the GitHub release gate.
    rel_branch = ""
    m_rel = re.search(r'if \[ "\$RELEASE_MODE" = "true" \];[\s\S]*?else', buildspec)
    if m_rel:
        rel_branch = m_rel.group(0)
    check("RELEASE_MODE build runs full validate (with tests), not --no-tests",
          "sdr.py validate" in rel_branch and "validate --no-tests" not in rel_branch)
    check("RELEASE_MODE build runs the reproducibility gate",
          "cmd_reproducibility" in rel_branch)

    # The ValidateProject in the publish pipeline must set RELEASE_MODE=true.
    vp = pipeline.split("ValidateProject:", 1)[-1].split("DriftCheckProject:", 1)[0]
    check("publish pipeline ValidateProject sets RELEASE_MODE",
          "RELEASE_MODE" in vp)
    check("ValidateProject RELEASE_MODE value is true",
          re.search(r'RELEASE_MODE[\s\S]{0,120}?"true"', vp) is not None
          or re.search(r'RELEASE_MODE[\s\S]{0,120}?true', vp) is not None)

    # Full-clone IAM: if the Source stage produces a CODEBUILD_CLONE_REF (git
    # full clone) artifact, the CodeBuild *service role* consuming it MUST hold
    # UseConnection scoped to the connection - AWS fails the initial full-clone
    # build otherwise, and GetConnection/GetConnectionToken alone do not cover
    # it. This guards against the permission silently regressing.
    uses_full_clone = "CODEBUILD_CLONE_REF" in pipeline
    check("Source stage requests a git full clone (CODEBUILD_CLONE_REF)",
          uses_full_clone)
    if uses_full_clone:
        # ValidateProject consumes the full-clone artifact and runs under
        # CodeBuildRole; that role's policy must grant UseConnection.
        vp_role = re.search(r'ServiceRole:\s*!GetAtt\s+(\w+)\.Arn', vp)
        role_name = vp_role.group(1) if vp_role else None
        check("ValidateProject runs under a named CodeBuild service role",
              role_name is not None)
        # Isolate that role's definition block in the template.
        role_block = ""
        if role_name:
            m = re.search(
                r'^\s{2}' + re.escape(role_name) + r':\n[\s\S]*?(?=\n\s{2}\w+:\n)',
                pipeline, re.MULTILINE)
            role_block = m.group(0) if m else ""
        check(f"{role_name or 'ValidateProject role'} grants codeconnections:UseConnection",
              "codeconnections:UseConnection" in role_block)
        check(f"{role_name or 'ValidateProject role'} grants codestar-connections:UseConnection",
              "codestar-connections:UseConnection" in role_block)

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
