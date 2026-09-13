#!/usr/bin/env python3
"""One entry point for the whole Security Decision Record (SDR) pipeline.

Nothing here does any work of its own. `sdr.py validate` runs the same
validation suite (validators + offline tests) that .github/workflows/validate.yml
runs via `python sdr.py validate`, so the local and CI VALIDATION SUITES cannot
drift. CI additionally enforces three gates OUTSIDE this command:
regenerate-and-diff, a double-build reproducibility check, and scanner-catalog
freshness. So a clean local run means the validation suite would pass in CI, not
that every CI gate would. If this file and that workflow ever disagree on the
suite, the workflow is correct and this file is the bug.

    python sdr.py all         build, validate, scan, then print a summary
    python sdr.py build       regenerate every deliverable
    python sdr.py validate    run the build gate (0 hard failures required)
    python sdr.py scan        run the readiness scanner (does not gate)
    python sdr.py clean       remove caches and scanner reports
    python sdr.py diff        show what a dataset change would affect
    python sdr.py review      report the human review register
    python sdr.py release     build, verify consistency, print the release tag

Exit codes: 0 success, 1 a step failed, 2 a dependency or path problem.
The readiness scanner's "findings exist" exit code is not a failure and is
not propagated; open findings are the normal state of an unfinished record.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(BASE, "validation", "scripts")
SDRSCAN = os.path.join(BASE, "automation", "sdrscan", "sdrscan.py")
VALIDATION_REPORT = os.path.join(BASE, "validation", "reports", "validation-report.json")
SCAN_REPORT_GLOB = os.path.join(BASE, "validation", "reports", "sdrscan", "sdrscan-class-*.json")
OFFERING_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")

# Build order matters. Each step reads what the step above it wrote:
# catalogs feed notes, notes feed profiles and the collector registry,
# profiles feed the record, the record feeds the Word file. Reordering these
# does not fail loudly; it silently builds against stale inputs.
BUILD_STEPS = [
    ("validate_upstream.py", "validate the pinned dataset against the official rules schema + lock"),
    ("build_catalogs.py", "rule and indicator catalogs from the pinned dataset"),
    ("build_notes.py", "per-rule notes and family name expansions"),
    ("build_profiles.py", "per-class profiles, Class C overlay, Class D register"),
    ("build_collector_registry.py", "indicator to read-only AWS check map"),
    ("build_sdr.py", "schema JSON, extensions companion, plain text record"),
    ("build_cpo.py", "Certification Package Overview (CPO-CSO-OVR)"),
    ("build_ocr.py", "example Ongoing Certification Report (CCM-OCR-AVL)"),
    ("build_scg.py", "Secure Configuration Guide scaffold (SCG-CSO-RSC/AUP)"),
    ("build_events.py", "example incident, SCN, and vulnerability artifacts"),
    ("automation/exporters/oscal_export.py", "OSCAL export of the SDR"),
    ("build_docx.py", "authoring Word document"),
    ("build_crosswalk.py", "NIST SP 800-53 Revision 5 to 20x crosswalk"),
    ("build_applicability_decisions.py", "applicability decision ledger (included and excluded, with reasons)"),
    ("build_assurance_graph.py", "unified assurance graph joining all artifacts"),
    ("build_release_manifest.py", "cryptographic release manifest of the package"),
    ("validate_package_consistency.py", "cross-artifact consistency check"),
    ("build_reports.py", "evidence-coverage and reviewer reports"),
    ("build_visualization.py", "self-contained HTML assurance-graph view"),
]

# The authoritative validation gate. `cmd_validate` runs every entry, and CI
# calls `python sdr.py validate` rather than listing scripts of its own, so the
# local and CI VALIDATION SUITES cannot drift. This is suite parity only: CI
# also runs regenerate-and-diff, a reproducibility gate, and scanner-catalog
# freshness outside this command. Paths are relative to the repository root.
VALIDATION_GATE = [
    ("validation/scripts/validate_sdr.py", "SDR schema, coverage, minimums, hygiene, content fidelity"),
    ("validation/scripts/validate_package.py", "CPO/OCR against official schemas"),
    ("validation/scripts/validate_cpo_semantics.py", "CPO rule-completeness (CPO-CSO-OVR/MTD, not just schema)"),
    ("validation/scripts/validate_assurance_graph.py", "assurance graph (full-chain traceability)"),
    ("validation/scripts/validate_reviews.py", "human review register (no machine-authored approvals)"),
    ("validation/scripts/validate_evidence.py", "live evidence-integrity gate (malformed/mismatched digests)"),
    ("validation/scripts/validate_package_consistency.py", "cross-artifact package consistency"),
]

# The full offline test suite CI runs. Same source of truth as CI.
TEST_SUITE = [
    "validation/scripts/test_sdr_semantic_roundtrip.py",
    "validation/scripts/test_package_build.py",
    "tests/test_cli.py",
    "validation/scripts/test_reviews.py",
    "tests/adversarial/run_adversarial.py",
    "tests/adversarial/test_e2e_tampering.py",
    "automation/collectors/test_collectors.py",
    "automation/collectors/test_collectors_scale.py",
    "automation/collectors/test_collectors_fixtures.py",
    "automation/collectors/test_multi_account.py",
    "automation/prefill/test_prefill.py",
    "automation/ai/test_draft_narratives.py",
    "automation/ai/test_explain_findings.py",
    "automation/ai/test_rollup_evidence.py",
    "automation/ai/test_review_overclaim.py",
    "automation/ai/test_suggest_ksi_mapping.py",
    "automation/metrics/test_append_metrics.py",
    "automation/metrics/test_metric_history_longitudinal.py",
    "automation/config-rules/test_evidence_existence_rule.py",
    "automation/config-rules/deploy/test_generate_templates.py",
    "automation/storage/test_provision_store.py",
    "automation/ai/test_bedrock_boundary.py",
    "validation/scripts/test_dataset_diff.py",
    "validation/scripts/test_change_impact.py",
    "validation/scripts/test_evidence_integrity.py",
    "validation/scripts/test_applicability.py",
    "automation/exporters/test_oscal_export.py",
    "automation/collectors/test_evidence_wiring.py",
    "automation/collectors/test_thirdparty_adapters.py",
    "automation/collectors/test_evidence_lifecycle.py",
    "examples/shift-left/test_run_policy.py",
    "automation/sdrscan/test_checks.py",
    "validation/scripts/test_submission_readiness.py",
]

REQUIRED_MODULES = [
    ("jsonschema", "jsonschema"),
    ("referencing", "referencing"),
    ("docx", "python-docx"),
]

RULE = "-" * 68


def out(line=""):
    print(line, flush=True)


def step_header(n, total, label):
    out()
    out(f"[{n}/{total}] {label}")
    out(RULE)


def run(script_path, args=None, label=None):
    """Run one pipeline script as a child process, streaming its output.

    Returns the child's exit code. Output is inherited rather than captured so
    that a long build shows progress, and so a traceback lands in the terminal
    where the reader expects it.
    """
    if not os.path.exists(script_path):
        out(f"FAIL. Missing script: {os.path.relpath(script_path, BASE)}")
        return 2
    cmd = [sys.executable, script_path] + list(args or [])
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=BASE)
    elapsed = time.monotonic() - started
    name = label or os.path.basename(script_path)
    if proc.returncode == 0:
        out(f"OK. {name} ({elapsed:.1f}s)")
    else:
        out(f"FAIL. {name} exited {proc.returncode} ({elapsed:.1f}s)")
    return proc.returncode


def _validation_gate_only():
    """Run the VALIDATION_GATE validators (no test suite), quietly, returning 0
    only if every gate passes. Used as a preflight precondition so a package
    that fails structural validation can never be reported submission-ready."""
    failures = 0
    for rel, _label in VALIDATION_GATE:
        proc = subprocess.run([sys.executable, os.path.join(BASE, rel)],
                              cwd=BASE, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
    return 1 if failures else 0


def check_dependencies():
    """Refuse to start rather than fail three steps in with an import error."""
    missing = []
    for module, package in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if sys.version_info < (3, 10):
        out(f"FAIL. Python 3.10 or newer is required; this is {sys.version.split()[0]}.")
        return False
    if missing:
        out("FAIL. Missing dependencies: " + ", ".join(missing))
        out("Install them with:")
        out("    pip install " + " ".join(missing))
        return False
    return True


def current_class():
    """The certification class the pipeline is currently building for."""
    try:
        with open(OFFERING_PROFILE, encoding="utf-8") as f:
            return (json.load(f).get("certification_class") or "?").upper()
    except (OSError, ValueError):
        return "?"


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def cmd_build(args):
    if not check_dependencies():
        return 2
    total = len(BUILD_STEPS)
    out(f"Building the Class {current_class()} Security Decision Record.")
    for i, (script, description) in enumerate(BUILD_STEPS, start=1):
        step_header(i, total, f"{script}: {description}")
        # Most steps live in validation/scripts; an entry containing a path
        # separator (e.g. automation/exporters/oscal_export.py) is resolved
        # against the repo root instead.
        script_path = (os.path.join(BASE, script) if ("/" in script or os.sep in script)
                       else os.path.join(SCRIPTS, script))
        code = run(script_path)
        if code != 0:
            out()
            out("Build stopped. Later steps read what this one writes, so "
                "continuing would build against stale inputs.")
            return 1
    out()
    out(f"Build complete. {total} steps, 0 failures.")
    return 0


def cmd_validate(args):
    if not check_dependencies():
        return 2
    out(f"Validating the Class {current_class()} record.")
    out(RULE)
    failures = []

    for rel, label in VALIDATION_GATE:
        code = run(os.path.join(BASE, rel), label=label)
        if code != 0:
            failures.append(rel)

    run_tests = not getattr(args, "no_tests", False)
    if run_tests:
        out()
        out("Offline test suite")
        out(RULE)
        for rel in TEST_SUITE:
            code = run(os.path.join(BASE, rel), label=os.path.basename(rel))
            if code != 0:
                failures.append(rel)
        # Some adversarial tests deliberately tamper a generated artifact and
        # run the validator, which overwrites validation-report.json with a
        # FAILED report before restoring the artifact. Re-run the SDR validator
        # once more so the canonical report on disk always reflects the real,
        # restored tree, never a leftover tampered-run report.
        out()
        out("Restoring canonical validation report (post-adversarial)")
        out(RULE)
        code = run(os.path.join(BASE, "validation/scripts/validate_sdr.py"),
                   label="validate_sdr.py (canonical restore)")
        if code != 0:
            failures.append("validation/scripts/validate_sdr.py (canonical restore)")

    out()
    if failures:
        out(f"The gate failed: {len(failures)} check(s) did not pass.")
        for rel in failures:
            out(f"    - {rel}")
        out("Nothing ships until every gate and test passes. Fix the cause in "
            "sdr/records/records-store.json, then rebuild. Never edit a "
            "generated file to make a check pass; content_fidelity_against_dataset "
            "exists to catch exactly that.")
        return 1
    scope = "gate + full offline test suite" if run_tests else "gate only"
    out(f"All validation passed ({scope}). This is the validation-suite gate "
        "CI runs via `python sdr.py validate`. CI additionally enforces "
        "regenerate-and-diff, a double-build reproducibility gate, and the "
        "scanner-catalog freshness check outside this command, so a clean local "
        "run means the validation suite would pass, not that every CI gate would.")
    return 0


def cmd_scan(args):
    out(f"Scanning assessment readiness for Class {current_class()}.")
    out(RULE)
    # Exit code 3 means the scanner found open findings. On an unfinished
    # record that is the expected state, not an error, so it is suppressed
    # here. Continuous integration suppresses it the same way.
    scan_args = [
        "--output-formats", "json,csv,html,txt",
        "--no-colour",
        "--ignore-exit-code-3",
    ]
    if args.only_fails:
        scan_args.append("--only-fails")
    code = run(SDRSCAN, scan_args, label="sdrscan.py")
    if code == 0:
        out(f"Reports written to {os.path.relpath(os.path.dirname(SCAN_REPORT_GLOB), BASE)}")
    return code


def cmd_explain(args):
    """Print a grounded, plain-language explanation of one rule or KSI."""
    explain_path = os.path.join(SCRIPTS, "explain.py")
    return run(explain_path, [args.identifier], label="explain.py")


def cmd_diff(args):
    """Show what a dataset change would affect, without editing anything.

    Give two dataset files to compare (an old and a new CR26 release); this runs
    the same dataset-diff and change-impact scripts the drift-check workflow
    runs, so a local `diff` and the daily automation agree. With no arguments it
    reports the last recorded change-impact artifact, if one exists.
    """
    code = 0
    old, new = getattr(args, "old", None), getattr(args, "new", None)
    if old and new:
        dd = os.path.join(SCRIPTS, "dataset_diff.py")
        ci = os.path.join(SCRIPTS, "change_impact.py")
        diff_out = os.path.join(BASE, "traceability", "dataset-diff.json")
        code = run(dd, [old, new, "--json", diff_out], label="dataset_diff.py")
        if code == 0:
            code = run(ci, ["--diff", diff_out,
                            "--json", os.path.join(BASE, "traceability", "change-impact.json")],
                       label="change_impact.py")
    elif old or new:
        out("Provide both an old and a new dataset file, or neither.")
        return 2

    impact = load_json(os.path.join(BASE, "traceability", "change-impact.json"))
    if impact:
        s = impact.get("source_summary", {})
        out()
        out("Change impact summary")
        out(RULE)
        out(f"Rules added      {s.get('added', 0)}")
        out(f"Rules removed    {s.get('removed', 0)}")
        out(f"Rules changed    {s.get('changed', 0)}")
        out(f"Requiring human review   {impact.get('total_requiring_review', 0)}")
        for rid in impact.get("rules_requiring_review", [])[:20]:
            out(f"    - {rid}")
        out()
        out("A dataset change never auto-changes a status or an approval. It "
            "flags what a human must re-examine.")
    else:
        out("No change-impact record found. Pass two dataset files to compare, "
            "e.g. `python sdr.py diff old.json new.json`, or let the daily "
            "drift-check workflow produce one.")
    return code


def cmd_review(args):
    """Report the human review register: what is approved, what is pending.

    Read-only. The pipeline never authors an approval; this only shows the
    state a human recorded.
    """
    register = load_json(os.path.join(BASE, "sdr", "reviews", "review-register.json"))
    out()
    out("Human review register")
    out(RULE)
    if not register:
        out("No review register found.")
        return 0
    reviews = register.get("reviews", [])
    if not reviews:
        out("Register present, no reviews recorded yet. Nothing is approved.")
        out()
        out("A reviewer records signoff in sdr/reviews/review-register.json. "
            "The pipeline cannot and will not do this.")
        return 0
    approved = [r for r in reviews if r.get("decision") == "approved"]
    other = [r for r in reviews if r.get("decision") != "approved"]
    out(f"Recorded reviews             {len(reviews)}")
    out(f"Approved                     {len(approved)}")
    out(f"Pending / other              {len(other)}")
    for r in other[:20]:
        out(f"    - {r.get('scope', '?')}: {r.get('decision', 'pending')} "
            f"(reviewer {r.get('reviewer', 'TBD')})")
    out()
    out("Approval is a human act. A green build proves the package is "
        "well-formed, not that it is approved or compliant.")
    return 0


def cmd_reproducibility():
    """Verify the build is reproducible: hash the deterministic artifacts,
    rebuild, and confirm they are byte-identical. Mirrors the CI reproducibility
    gate so `release` verifies reproducibility rather than merely asserting it.
    Returns 0 if reproducible, 1 otherwise. Excludes *.docx (its zip container
    embeds timestamps)."""
    import hashlib

    watch_dirs = ["sdr", "package", "traceability", "artifacts", "validation/reports"]
    exts = (".json", ".txt", ".md", ".csv")

    def fingerprint():
        digests = {}
        for d in watch_dirs:
            root = os.path.join(BASE, d)
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    if fn.endswith(exts) and not fn.endswith(".docx"):
                        p = os.path.join(dirpath, fn)
                        h = hashlib.sha256()
                        with open(p, "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                h.update(chunk)
                        digests[os.path.relpath(p, BASE)] = h.hexdigest()
        return digests

    out("Reproducibility check (double build, byte comparison)")
    out(RULE)
    first = fingerprint()
    code = cmd_build(argparse.Namespace(only_fails=False, no_tests=True))
    if code != 0:
        out("FAIL. Rebuild failed during reproducibility check.")
        return 1
    second = fingerprint()
    changed = sorted(k for k in set(first) | set(second) if first.get(k) != second.get(k))
    if changed:
        out(f"FAIL. {len(changed)} deterministic artifact(s) changed across two builds:")
        for k in changed[:20]:
            out(f"    - {k}")
        return 1
    out(f"Reproducible: {len(second)} deterministic artifacts byte-identical across two builds.")
    return 0


def cmd_release(args):
    """Produce and report a release: build, run the FULL validation gate and
    test suite, verify reproducibility, then print the tag.

    Runs the same validation suite CI runs (via cmd_validate) AND a local
    double-build reproducibility check, so `release` verifies what it claims.
    Always runs the full test suite (no --no-tests escape). Does not tag git or
    publish anything.
    """
    # A release is not allowed to skip its own tests.
    args.no_tests = False
    code = cmd_build(args)
    if code != 0:
        out("Build failed; not a releasable state.")
        return code
    out()
    code = cmd_validate(args)
    if code != 0:
        out("Validation gate failed; not releasable.")
        return code
    out()
    code = cmd_reproducibility()
    if code != 0:
        out("Reproducibility check failed; not releasable.")
        return code
    manifest = load_json(os.path.join(BASE, "artifacts", "release-manifest.json"))
    out()
    out("Release")
    out(RULE)
    if manifest:
        out(f"Release tag                  {manifest.get('release_tag', '?')}")
        out(f"Framework version            {manifest.get('framework_version', '?')}")
        out(f"Dataset version              {manifest.get('dataset_version', '?')}")
        out(f"Artifacts fingerprinted      {manifest.get('artifact_count', '?')}")
    out()
    out("This is a build-provenance record, not a compliance determination. A "
        "passing release gate means well-formed, consistent, and verified "
        "reproducible (double-build byte-identical, checked just now); "
        "certification is an accredited assessor and authorizing-body decision.")
    out(f"To tag: git tag {manifest.get('release_tag', '<tag>') if manifest else '<tag>'}")
    return 0


def cmd_preflight(args):
    """FedRAMP submission preflight: check for submission BLOCKERS.
    Structural validity (the build gate) is necessary but not sufficient to
    submit. FedRAMP requires the initial package to represent the current
    offering and be freshly provider-verified. This reports blockers; it never
    says "compliant" and never changes a status. Grounded in the pinned dataset:
      FRC-APP-FCP (MUST): fresh initial package verified/validated by the
        provider within the previous 7 days.
      FRC-CLA-ASF / FRC-CLA-EAM (MUST, Class A): alternative-framework
        assessment within the past 12 months, and External Assessment Materials
        supplied.
    """
    import datetime as _dt
    offering = load_json(OFFERING_PROFILE) or {}
    cls = current_class().lower()
    blockers = []
    warnings = []

    # A package cannot be "submission ready" if it does not even pass the
    # validation gate (schema, semantic completeness, evidence integrity, review
    # integrity, assurance graph, package consistency). Run the gate-only path
    # (validators, no tests) as a hard precondition.
    out("Preflight precondition: running the validation gate...")
    if _validation_gate_only() != 0:
        blockers.append("the validation gate does not pass (schema/semantic/"
                        "evidence/review/consistency); submission is impossible "
                        "until `python sdr.py validate` is clean")

    def _is_tbd(v):
        return v is None or str(v).strip() == "" or str(v).strip().startswith("TBD") \
            or "placeholder" in str(v).lower() or "has not been provided" in str(v).lower()

    def _parse_dt(value):
        """Return (datetime, error). Requires timezone-aware; rejects future."""
        s = str(value).replace("Z", "+00:00")
        try:
            dt = _dt.datetime.fromisoformat(s)
        except ValueError:
            return None, "not a valid ISO datetime"
        if dt.tzinfo is None:
            return None, "must be timezone-aware (include an offset or Z)"
        if dt > _dt.datetime.now(_dt.timezone.utc):
            return None, "is in the future"
        return dt, None

    # Required offering-profile fields. Everything not on the optional allowlist
    # that is still a TBD is a submission blocker, not a warning.
    OPTIONAL_FIELDS = {
        "profile_note", "evidence_sources", "external_assessment",
        "provider_verified_at", "dr_region", "iac_technology",
        "materials_item_schema", "note",
    }
    REQUIRED_FIELDS = [
        "organization_name", "offering_name", "offering_abbreviation",
        "business_purpose", "service_model", "deployment_model",
        "certification_type", "certification_class", "aws_partition",
        "primary_region", "management_plane", "federal_information_types",
        "certification_package_overview_uri", "security_contact",
        "incident_contact", "assessor", "evidence_retention",
    ]
    unresolved_required = [f for f in REQUIRED_FIELDS if _is_tbd(offering.get(f))]
    if unresolved_required:
        blockers.append(f"{len(unresolved_required)} required offering-profile "
                        f"field(s) unresolved (TBD/placeholder): "
                        f"{', '.join(unresolved_required)}")

    # FRC-APP-FCP: provider verification freshness (7 days, real timedelta).
    verified = offering.get("provider_verified_at")
    if _is_tbd(verified):
        blockers.append("provider_verified_at is not set (FRC-APP-FCP requires "
                        "verification/validation within the previous 7 days)")
    else:
        dt, err = _parse_dt(verified)
        if err:
            blockers.append(f"provider_verified_at {err}: {verified}")
        elif (_dt.datetime.now(_dt.timezone.utc) - dt) > _dt.timedelta(days=7):
            blockers.append("provider_verified_at is older than 7 days "
                            "(FRC-APP-FCP requires within the previous 7 days)")

    # Class A: external assessment materials (FRC-CLA-ASF / EAM).
    if cls == "a":
        ext = offering.get("external_assessment") or {}
        if not ext or _is_tbd(ext.get("framework")) or _is_tbd(ext.get("assessment_date")):
            blockers.append("Class A: external_assessment not populated "
                            "(FRC-CLA-ASF/EAM require alternative-framework "
                            "assessment materials from the past 12 months)")
        else:
            adate = ext.get("assessment_date")
            try:
                when = _dt.date.fromisoformat(str(adate))
                if when > _dt.date.today():
                    blockers.append(f"Class A: assessment_date is in the future: {adate}")
                elif (_dt.date.today() - when) > _dt.timedelta(days=365):
                    blockers.append(f"Class A: external assessment {adate} is "
                                    f"older than 12 months (FRC-CLA-ASF)")
            except ValueError:
                blockers.append(f"Class A: assessment_date not a valid date: {adate}")
            materials = ext.get("materials") or []
            if not materials:
                blockers.append("Class A: external_assessment.materials empty "
                                "(FRC-CLA-EAM: supply the assessment materials as references)")
            else:
                for i, m in enumerate(materials):
                    if not isinstance(m, dict) or _is_tbd(m.get("type")) \
                            or _is_tbd(m.get("uri")) or _is_tbd(m.get("sha256")):
                        blockers.append(f"Class A: materials[{i}] missing "
                                        f"type/uri/sha256 (FRC-CLA-EAM)")

    # FRC-APP-FIA: a fresh FedRAMP independent assessment within 3 months.
    # Class B and C MUST; Class A MAY (so not a blocker for A). FRC-APP-USA
    # allows freshening a stale assessment unless it is more than 9 months old.
    if cls in ("b", "c"):
        fia = offering.get("fedramp_independent_assessment") or {}
        completed = fia.get("completed_at")
        if _is_tbd(fia.get("assessor_name")) or _is_tbd(completed):
            blockers.append(f"Class {cls.upper()}: fedramp_independent_assessment "
                            "not populated (FRC-APP-FIA MUST: a fresh FedRAMP "
                            "independent assessment by a FedRAMP Recognized service "
                            "within the previous 3 months)")
        else:
            try:
                when = _dt.date.fromisoformat(str(completed))
                if when > _dt.date.today():
                    blockers.append(f"Class {cls.upper()}: FIA completed_at is in the future: {completed}")
                else:
                    age = _dt.date.today() - when
                    if age > _dt.timedelta(days=274):  # ~9 months: even freshening is barred
                        blockers.append(f"Class {cls.upper()}: FedRAMP independent assessment "
                                        f"{completed} is older than 9 months; FRC-APP-USA "
                                        "freshening no longer applies - a new assessment is required")
                    elif age > _dt.timedelta(days=91):  # >3 months: needs freshening
                        warnings.append(f"Class {cls.upper()}: FedRAMP independent assessment "
                                        f"{completed} is older than 3 months (FRC-APP-FIA); a "
                                        "FRC-APP-USA freshening review by a Recognized assessor is required")
            except ValueError:
                blockers.append(f"Class {cls.upper()}: FIA completed_at not a valid date: {completed}")
        # CPO-CSO-OSA: B/C MUST include the assessor overall summary in the CPO.
        if _is_tbd(offering.get("overall_assessment_summary")):
            blockers.append(f"Class {cls.upper()}: overall_assessment_summary not set "
                            "(CPO-CSO-OSA MUST: include the assessor's overall assessment "
                            "summary from IVV-IAS-OSA in the CPO)")

    # CDS-CSO-AVR: availability reporting web service. Class B/C MUST, A SHOULD.
    avr = offering.get("availability_reporting") or {}
    avr_missing = (_is_tbd(avr.get("human_readable_uri")) or _is_tbd(avr.get("machine_readable_uri")))
    if cls in ("b", "c"):
        if avr_missing:
            blockers.append(f"Class {cls.upper()}: availability_reporting requires BOTH a "
                            "human_readable_uri AND a machine_readable_uri (CDS-CSO-AVR MUST)")
        else:
            hist = avr.get("history_days")
            if isinstance(hist, int) and hist < 30 or (isinstance(hist, str) and hist.isdigit() and int(hist) < 30):
                blockers.append(f"Class {cls.upper()}: availability history is < 30 days (CDS-CSO-AVR)")
            elif _is_tbd(hist):
                blockers.append(f"Class {cls.upper()}: availability_reporting.history_days not set (CDS-CSO-AVR: >= 30)")
            if avr.get("available_when_primary_unavailable") is not True:
                warnings.append(f"Class {cls.upper()}: availability service must remain available when "
                                "the primary offering is down (CDS-CSO-AVR); confirm and set "
                                "available_when_primary_unavailable=true (human-verified)")
    elif cls == "a" and avr_missing:
        warnings.append("Class A: availability_reporting is a SHOULD (CDS-CSO-AVR); not set")

    # FRC-CSX-MOT: historical KSI metrics from persistent validation. Class C
    # MUST have >= 6 months for all KSIs; Class D >= 18 months; A/B advisory.
    # Distinct from SDR-CSX-KMT formatting; this is a duration requirement.
    mot_min_days = {"c": 183, "d": 548}.get(cls)
    if mot_min_days:
        history = load_json(os.path.join(BASE, "automation", "metrics", "metric-history.json"))
        if not history:
            blockers.append(f"Class {cls.upper()}: no KSI metric history found "
                            f"(FRC-CSX-MOT MUST: persistent-validation history over at "
                            f"least {'6' if cls == 'c' else '18'} months for all KSIs)")
        else:
            per = history.get("ksis", history) if isinstance(history, dict) else {}
            short = []
            # Compute span per KSI from datapoint dates.
            import datetime as _d2
            today = _d2.date.today()
            for kid, entries in (per.items() if isinstance(per, dict) else []):
                dates = []
                for e in (entries if isinstance(entries, list) else []):
                    ds_ = (e or {}).get("date") if isinstance(e, dict) else None
                    if ds_:
                        try:
                            dates.append(_d2.date.fromisoformat(str(ds_)[:10]))
                        except ValueError:
                            pass
                if not dates or (today - min(dates)) < _d2.timedelta(days=mot_min_days):
                    short.append(kid)
            if short:
                blockers.append(f"Class {cls.upper()}: {len(short)} KSI(s) lack "
                                f"{'6' if cls == 'c' else '18'} months of persistent-"
                                f"validation history (FRC-CSX-MOT)")
    elif cls in ("a", "b"):
        # A MAY, B SHOULD - advisory only.
        history = load_json(os.path.join(BASE, "automation", "metrics", "metric-history.json"))
        if not history:
            warnings.append(f"Class {cls.upper()}: no KSI metric history yet "
                            f"(FRC-CSX-MOT is {'MAY' if cls == 'a' else 'SHOULD'} at this class)")

    # Record store: bulk unresolved content stays a readiness warning (FedRAMP
    # explicitly allows an honestly incomplete implementation). Count TBDs only
    # within the records APPLICABLE to this class - counting the whole file
    # would report TBDs in rules that do not apply (e.g. Class A resolves far
    # fewer rules than the file contains), which is misleading.
    records = load_json(os.path.join(BASE, "sdr", "records", "records-store.json")) or {}
    class_profile = load_json(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json")) or {}
    applicable_frr = {r.get("rule_id") for r in class_profile.get("rules", [])}
    ksi_profile = load_json(os.path.join(BASE, "profiles", "common", "ksi-profile.json")) or {}
    applicable_ksi = {k.get("ksi_id") for k in ksi_profile.get("indicators", [])}

    def _count_markers(rec):
        blob = json.dumps(rec)
        return blob.count("TBD"), blob.count("sdr://placeholder/")

    def _is_unanswered(rec):
        """An applicable record is UNANSWERED (a submission blocker) when its
        implementation is still the generic 'has not been provided' placeholder
        or an empty/TBD implementation. This is different from an honest
        Not Implemented record that carries a real rationale/risk/owner - FedRAMP
        allows the latter, but a placeholder is not implementation information."""
        impl = rec.get("implementation")
        impl_txt = json.dumps(impl) if impl is not None else ""
        status = str(rec.get("implementation_status", ""))
        if not impl or "has not been provided" in impl_txt or "TBD:" in impl_txt:
            return True
        # A Not Implemented / Partially Implemented status must carry rationale.
        if status in ("Not Implemented", "Partially Implemented"):
            ext = rec.get("extension", {}) or {}
            has_rationale = any(not _is_tbd(ext.get(k)) for k in
                                ("customer_risk", "failure_response", "responsibility"))
            return not has_rationale
        return False

    tbd = placeholders = scoped_records = 0
    unanswered = []
    for rid, rec in (records.get("frr", {}) or {}).items():
        if rid in applicable_frr:
            t, p = _count_markers(rec); tbd += t; placeholders += p; scoped_records += 1
            if _is_unanswered(rec):
                unanswered.append(rid)
    for kid, rec in (records.get("ksi", {}) or {}).items():
        if kid in applicable_ksi:
            t, p = _count_markers(rec); tbd += t; placeholders += p; scoped_records += 1
            if _is_unanswered(rec):
                unanswered.append(kid)
    if tbd:
        warnings.append(f"{tbd} unresolved TBD placeholder(s) across {scoped_records} "
                        f"records applicable to Class {cls.upper()}")
    if placeholders:
        warnings.append(f"{placeholders} unresolved sdr://placeholder/ evidence URI(s) "
                        f"in applicable records")
    if unanswered:
        sample = ", ".join(unanswered[:8])
        blockers.append(f"{len(unanswered)} applicable requirement(s) have no "
                        f"implementation information (still placeholder/TBD, not an "
                        f"honest Not-Implemented with rationale): {sample}"
                        + (" ..." if len(unanswered) > 8 else ""))

    # Scan the GENERATED submission artifacts, not merely the input profile. A
    # generated CPO carrying template markers, placeholder IDs/URLs, or recorded
    # _cpoAssumptions must not reach "submission ready".
    cpo = load_json(os.path.join(BASE, "package", "cpo", "cpo.json")) or {}
    si = cpo.get("serviceIdentification", {}) or {}
    cpo_markers = []
    if str(si.get("fedRampPackageId", "")).startswith("TBD"):
        cpo_markers.append("fedRampPackageId is TBD-PACKAGE-ID")
    for field in ("website", "logo"):
        if "placeholder" in str(si.get(field, "")).lower():
            cpo_markers.append(f"CPO {field} is a placeholder URL")
    assessor = cpo.get("assessor", {}) or {}
    if assessor.get("assessorID") == "000000":
        cpo_markers.append("CPO assessorID is the 000000 placeholder")
    sp = cpo.get("serviceProperties", {}) or {}
    for key in ("trustCenter", "secureConfigurationGuidance"):
        url = (sp.get(key) or {}).get("url", "")
        if "placeholder" in str(url).lower() or "example" in str(url).lower():
            cpo_markers.append(f"CPO {key} is a placeholder URL")
    if cpo.get("_cpoAssumptions"):
        cpo_markers.append(f"CPO contains {len(cpo['_cpoAssumptions'])} unresolved "
                           "generator assumption(s) (see _cpoAssumptions)")
    if cpo_markers:
        blockers.append(f"generated CPO carries {len(cpo_markers)} template "
                        f"marker(s)/assumption(s): {'; '.join(cpo_markers)}")

    # CPO semantic completeness (CPO-CSO-OVR / CPO-CSO-MTD): required-information
    # items and metadata must be resolved, not TBD.
    mtd = cpo.get("xCpoMetadata", {}) or {}
    mtd_gaps = [f for f in ("responsible_official", "version", "last_updated", "source_of_update")
                if _is_tbd(mtd.get(f))]
    if mtd_gaps:
        blockers.append(f"CPO metadata unresolved (CPO-CSO-MTD): {', '.join(mtd_gaps)}")
    req_info = (cpo.get("xCpoRequiredInformation", {}) or {}).get("items", [])
    req_gaps = [i.get("rule") for i in req_info if _is_tbd(i.get("provider_content"))]
    if req_gaps:
        blockers.append(f"CPO required information unresolved (CPO-CSO-OVR): "
                        f"{', '.join(str(r) for r in req_gaps)}")

    # document_review_needed: an applicable rule whose upstream family document
    # is in an unfamiliar/placeholder lifecycle state must be human-reviewed
    # before submission (fail safe, not silently treated as ordinary content).
    decisions = load_json(os.path.join(BASE, "traceability", "applicability-decisions.json")) or {}
    needs_doc_review = [d.get("rule_id") for d in decisions.get("decisions", [])
                        if d.get("applicable") and d.get("document_review_needed")]
    if needs_doc_review:
        sample = ", ".join(str(r) for r in needs_doc_review[:8])
        blockers.append(f"{len(needs_doc_review)} applicable rule(s) are in a family "
                        f"with an unfamiliar/placeholder document lifecycle state and "
                        f"need human review before submission: {sample}"
                        + (" ..." if len(needs_doc_review) > 8 else ""))

    # Package component that is required but not implemented (from the manifest).
    manifest_pkg = load_json(os.path.join(BASE, "package",
                                          "certification-package-manifest.json")) or {}
    for name, comp in (manifest_pkg.get("certification_package", {}) or {}).items():
        req = comp.get("required_for_initial_package")
        required_here = req is True or (isinstance(req, str) and cls.upper() in req.upper())
        if required_here and comp.get("status") in ("partial", "not_implemented"):
            blockers.append(f"required package component '{name}' is "
                            f"'{comp.get('status')}' (a required component must be "
                            "complete, or its missing portion proven non-applicable "
                            "to this class, before submission)")

    # Package-level signoff MUST reference the current release-manifest hash.
    # One approved node in the assurance review register is NOT package approval.
    register = load_json(os.path.join(BASE, "sdr", "reviews", "review-register.json")) or {}
    signoff = register.get("package_signoff")
    manifest_path = os.path.join(BASE, "artifacts", "release-manifest.json")
    manifest = load_json(manifest_path) or {}
    manifest_tag = manifest.get("release_tag")
    # Cryptographic binding: the SHA-256 of the exact manifest bytes the human
    # signed. The tag (v1.0.0-cr26-...) can stay identical while provider facts,
    # evidence, CPO, or SDR contents change; the hash cannot.
    import hashlib as _hashlib
    actual_manifest_sha = None
    if os.path.isfile(manifest_path):
        with open(manifest_path, "rb") as _mf:
            actual_manifest_sha = "sha256:" + _hashlib.sha256(_mf.read()).hexdigest()
    if not signoff or signoff.get("decision") != "approved":
        blockers.append("no package_signoff recorded as approved "
                        "(package-level provider signoff is required to submit; "
                        "a single approved assurance node is not package approval)")
    else:
        signed_tag = signoff.get("release_tag") or signoff.get("release_manifest_tag")
        if manifest_tag and signed_tag != manifest_tag:
            blockers.append(f"package_signoff is for a different release "
                            f"({signed_tag}) than the current manifest ({manifest_tag}); "
                            f"re-sign against the current package")
        # The binding check: the signed manifest hash MUST equal the current one.
        signed_sha = signoff.get("package_manifest_sha256")
        if _is_tbd(signed_sha):
            blockers.append("package_signoff.package_manifest_sha256 not set "
                            "(the signoff must be bound to the exact manifest bytes)")
        elif actual_manifest_sha and signed_sha != actual_manifest_sha:
            blockers.append("package_signoff.package_manifest_sha256 does not match "
                            "the current release manifest; a generated artifact "
                            "changed since signoff - re-review and re-sign")
        for req in ("reviewer", "timestamp"):
            if _is_tbd(signoff.get(req)):
                blockers.append(f"package_signoff.{req} not set")

    # Application-scope prerequisites (application-preflight only): FedRAMP's
    # applying rules require the provider to already be listed in the FedRAMP
    # Marketplace and to complete the FedRAMP Certification Application Form.
    # These are NOT properties of the generated package, so package-preflight
    # does not check them; application-preflight does.
    scope = getattr(args, "command", "preflight")
    application_scope = scope in ("application-preflight", "preflight")
    if application_scope:
        app = offering.get("application_prerequisites") or {}
        if _is_tbd(app.get("marketplace_listing_uri")):
            blockers.append("application: provider is not confirmed listed in the "
                            "FedRAMP Marketplace (set application_prerequisites."
                            "marketplace_listing_uri)")
        if _is_tbd(app.get("application_form_reference")):
            blockers.append("application: FedRAMP Certification Application Form not "
                            "referenced (set application_prerequisites.application_form_reference)")

    out()
    label = ("FedRAMP APPLICATION preflight" if scope == "application-preflight"
             else "FedRAMP PACKAGE preflight" if scope == "package-preflight"
             else "FedRAMP submission preflight")
    out(f"{label} (Class {cls.upper()})")
    out(RULE)
    if blockers:
        out(f"SUBMISSION BLOCKERS ({len(blockers)}):")
        for b in blockers:
            out(f"    [BLOCK] {b}")
    if warnings:
        out(f"Warnings ({len(warnings)}):")
        for w in warnings:
            out(f"    [WARN]  {w}")
    out()
    if blockers:
        out("NOT ready. Resolve the blockers above. This is a readiness check, "
            "not a compliance determination; FedRAMP and its recognized assessor "
            "determine compliance.")
        return 1
    if scope == "package-preflight":
        out("Package ready: the generated Certification Package has no blockers "
            "(required fields filled, fresh provider verification, package-level "
            "signoff bound to the current manifest). This is NOT an application-"
            "readiness statement - run `sdr.py application-preflight` to also "
            "check Marketplace listing and the application form. Not a compliance "
            "or certification claim.")
    else:
        out("Application ready: no blockers found - the package is complete and "
            "the FedRAMP application prerequisites (Marketplace listing, "
            "application form) are referenced. This does NOT mean compliant or "
            "certified; that is FedRAMP's determination.")
    return 0


def cmd_clean(args):
    """Remove regenerable local clutter only.

    Deliberately does not delete generated deliverables. They are committed on
    purpose, because the repository ships as a working template that someone
    should be able to read before they can run anything.
    """
    removed = []
    for root, dirs, _files in os.walk(BASE):
        if ".git" in root.split(os.sep):
            continue
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                removed.append(os.path.relpath(os.path.join(root, d), BASE))
                dirs.remove(d)
    scan_dir = os.path.dirname(SCAN_REPORT_GLOB)
    if os.path.isdir(scan_dir):
        shutil.rmtree(scan_dir, ignore_errors=True)
        removed.append(os.path.relpath(scan_dir, BASE))
    for log in glob.glob(os.path.join(BASE, "*.log")):
        os.remove(log)
        removed.append(os.path.relpath(log, BASE))

    if removed:
        out(f"Removed {len(removed)} items:")
        for item in sorted(removed):
            out(f"    {item}")
    else:
        out("Nothing to remove.")
    out()
    out("Generated deliverables were left in place. They are committed on "
        "purpose. To prove they are reproducible, run `python sdr.py build` "
        "and then `git diff`; an empty diff is the guarantee.")
    return 0


def summary():
    """Print what a reader actually wants after a run: am I ready, and how far off."""
    out()
    out("Readiness summary")
    out(RULE)
    cls = current_class()
    out(f"Certification class          Class {cls}")

    report = load_json(VALIDATION_REPORT)
    if report is None:
        out("Build gate                   no report found")
    else:
        hard = report.get("hard_failures", "?")
        checks = report.get("checks", [])
        passed = sum(1 for c in checks if c.get("result") == "PASS")
        # The report does not record whether a check is hard or advisory, so a
        # FAIL that did not raise the hard count must be an advisory one.
        soft = [c["check"] for c in checks if c.get("result") == "FAIL"]
        verdict = "SHIPPABLE" if hard == 0 else "BLOCKED"
        out(f"Build gate                   {verdict}, hard failures: {hard}")
        out(f"Checks                       {passed} of {len(checks)} passing")
        if hard == 0 and soft:
            out(f"Advisory failures            {', '.join(soft)}")
        out(f"Dataset                      {report.get('generated', 'unknown')}")

    scan_files = sorted(glob.glob(SCAN_REPORT_GLOB))
    if not scan_files:
        out("Assessment readiness         not scanned")
    else:
        scan = load_json(scan_files[-1]) or {}
        s = scan.get("summary", {})
        if s:
            out(f"Assessment readiness         {s.get('readiness_percent', '?')}% "
                f"({s.get('pass', '?')} pass, {s.get('fail', '?')} fail, "
                f"{s.get('manual', '?')} manual of {s.get('total', '?')} findings)")
    out()
    out("Next step: open sdr/records/records-store.json and replace the "
        "placeholders for the rules and indicators you own. "
        "See docs/implementation-guide.md.")


def cmd_all(args):
    code = cmd_build(args)
    if code != 0:
        return code
    out()
    code = cmd_validate(args)
    validate_failed = code != 0
    out()
    scan_code = cmd_scan(args)
    summary()
    if validate_failed:
        return 1
    return 0 if scan_code == 0 else 1


def build_parser():
    p = argparse.ArgumentParser(
        prog="sdr.py",
        description="Build, validate and scan a FedRAMP 20x Security Decision Record.",
        epilog="Run `python sdr.py all` first. Everything else is a subset of it.",
    )
    sub = p.add_subparsers(dest="command")

    sub.add_parser("build", help="regenerate every deliverable from the record store")
    val_p = sub.add_parser("validate", help="run the full gate + offline test suite (CI parity)")
    val_p.add_argument("--no-tests", action="store_true",
                       help="run validators only, skip the offline test suite (faster)")

    scan = sub.add_parser("scan", help="run the readiness scanner (reports, does not gate)")
    scan.add_argument("--only-fails", action="store_true",
                      help="report only open findings, omitting what already passes")

    all_p = sub.add_parser("all", help="build, validate, scan, then summarize")
    all_p.add_argument("--only-fails", action="store_true",
                       help="passed through to the scanner")
    all_p.add_argument("--no-tests", action="store_true",
                       help="skip the offline test suite in the validate step")

    sub.add_parser("clean", help="remove caches and scanner reports")

    explain_p = sub.add_parser(
        "explain", help="explain one rule or KSI in plain language (grounded in the dataset)")
    explain_p.add_argument("identifier", help="a rule id (FRC-CSO-PKG) or KSI id (KSI-CNA-RNT)")

    diff_p = sub.add_parser("diff", help="show what a dataset change would affect (read-only)")
    diff_p.add_argument("old", nargs="?", help="old dataset JSON (optional)")
    diff_p.add_argument("new", nargs="?", help="new dataset JSON (optional)")
    sub.add_parser("review", help="report the human review register (read-only)")
    rel_p = sub.add_parser("release", help="build, run the full gate + reproducibility, print the tag")
    sub.add_parser("preflight", help="alias for application-preflight (read-only)")
    sub.add_parser("package-preflight", help="check the generated package for submission blockers (read-only)")
    sub.add_parser("application-preflight", help="package checks PLUS FedRAMP application prerequisites (read-only)")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if not hasattr(args, "only_fails"):
        args.only_fails = False
    if not hasattr(args, "no_tests"):
        args.no_tests = False
    handlers = {
        "build": cmd_build,
        "validate": cmd_validate,
        "scan": cmd_scan,
        "all": cmd_all,
        "clean": cmd_clean,
        "explain": cmd_explain,
        "diff": cmd_diff,
        "review": cmd_review,
        "release": cmd_release,
        "preflight": cmd_preflight,
        "package-preflight": cmd_preflight,
        "application-preflight": cmd_preflight,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())






