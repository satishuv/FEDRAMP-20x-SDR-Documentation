#!/usr/bin/env python3
"""One entry point for the whole Security Decision Record (SDR) pipeline.

Nothing here does any work of its own. It runs the same scripts, in the same
order, that .github/workflows/validate.yml runs, so a passing local run and a
passing continuous integration run mean the same thing. If this file and that
workflow ever disagree, the workflow is correct and this file is the bug.

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
    code = run(os.path.join(SCRIPTS, "validate_sdr.py"), label="validate_sdr.py")
    if code != 0:
        out()
        out("The gate failed. Nothing ships until hard failures reach 0.")
        out("Fix the cause in sdr/records/records-store.json, then rebuild. "
            "Never edit a generated file to make a check pass; "
            "content_fidelity_against_dataset exists to catch exactly that.")
    return code


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


def cmd_release(args):
    """Produce and report a release: build, verify consistency, print the tag.

    Does not tag git or publish anything; it prints the release manifest tag
    and confirms the package is internally consistent and reproducible-shaped.
    """
    code = cmd_build(args)
    if code != 0:
        out("Build failed; not a releasable state.")
        return code
    consistency = os.path.join(SCRIPTS, "validate_package_consistency.py")
    if os.path.exists(consistency):
        code = run(consistency, [], label="validate_package_consistency.py")
        if code != 0:
            out("Cross-artifact consistency failed; not releasable.")
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
        "passing release gate means well-formed, consistent and reproducible; "
        "certification is an accredited assessor and authorizing-body decision.")
    out(f"To tag: git tag {manifest.get('release_tag', '<tag>') if manifest else '<tag>'}")
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
    sub.add_parser("validate", help="run the build gate; 0 hard failures required to ship")

    scan = sub.add_parser("scan", help="run the readiness scanner (reports, does not gate)")
    scan.add_argument("--only-fails", action="store_true",
                      help="report only open findings, omitting what already passes")

    all_p = sub.add_parser("all", help="build, validate, scan, then summarize")
    all_p.add_argument("--only-fails", action="store_true",
                       help="passed through to the scanner")

    sub.add_parser("clean", help="remove caches and scanner reports")

    explain_p = sub.add_parser(
        "explain", help="explain one rule or KSI in plain language (grounded in the dataset)")
    explain_p.add_argument("identifier", help="a rule id (FRC-CSO-PKG) or KSI id (KSI-CNA-RNT)")

    diff_p = sub.add_parser("diff", help="show what a dataset change would affect (read-only)")
    diff_p.add_argument("old", nargs="?", help="old dataset JSON (optional)")
    diff_p.add_argument("new", nargs="?", help="new dataset JSON (optional)")
    sub.add_parser("review", help="report the human review register (read-only)")
    sub.add_parser("release", help="build, verify consistency, print the release tag")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if not hasattr(args, "only_fails"):
        args.only_fails = False
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
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())



