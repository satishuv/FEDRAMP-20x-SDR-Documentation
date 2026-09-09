#!/usr/bin/env python3
"""Local shift-left policy runner (CI/CD pre-deploy gate).

Sibling to the SDR framework: checks INFRASTRUCTURE-as-code before deploy,
mirroring the AWS Security Assurance Services compliance-engineering demo
(an OPA / CFN Guard stage in the pipeline). This runner evaluates the same
intent as policy/s3_tls.rego: every aws_s3_bucket must have a bucket policy
that denies non-TLS access (aws:SecureTransport = false).

Two ways to evaluate, same verdict:
  - If the `opa` binary is on PATH, this shells out to it against the .rego
    file (the real OPA engine).
  - Otherwise it uses a pure-Python evaluator of the identical rule, so the
    check runs in CI with no extra tooling.

Pipeline semantics (like the demo):
  - PASS  -> silent, exit 0.
  - FAIL  -> prints each violation and exits 1 (blocks the deploy). Use
             --alert to report violations but still exit 0 (dev/alert mode).
  - --evidence PATH writes a small JSON evidence record of the run (for feeding
    a trust center / monitoring), regardless of pass or fail.

Offline, dependency-free. Runs under pytest via its importable functions, or
directly:
    python examples/shift-left/run_policy.py examples/shift-left/fixtures/plan-compliant.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys


def _iter_resources(plan):
    """Yield resources from either a simplified {"resources":[]} shape or a
    terraform `show -json` plan (planned_values.root_module.resources)."""
    for r in plan.get("resources", []) or []:
        yield r
    pv = plan.get("planned_values", {}).get("root_module", {}).get("resources", [])
    for r in pv:
        yield r


def _policy_enforces_tls(policy_json):
    if not policy_json:
        return False
    try:
        policy = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
    except (ValueError, TypeError):
        return False
    for stmt in policy.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Deny":
            continue
        cond = stmt.get("Condition", {}).get("Bool", {})
        # Deny when aws:SecureTransport is false = enforce TLS.
        if str(cond.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


def evaluate(plan):
    """Pure-Python evaluation. Returns a list of violation message strings
    (empty == compliant)."""
    buckets = []
    tls_buckets = set()
    for r in _iter_resources(plan):
        rtype = r.get("type")
        values = r.get("values", {}) or {}
        if rtype == "aws_s3_bucket":
            buckets.append(values.get("bucket") or r.get("name"))
        elif rtype == "aws_s3_bucket_policy":
            if _policy_enforces_tls(values.get("policy")):
                name = values.get("bucket")
                if name:
                    tls_buckets.add(name)
    violations = []
    for b in buckets:
        if b not in tls_buckets:
            violations.append(
                f"S3 bucket '{b}' has no policy denying non-TLS "
                "(aws:SecureTransport=false) access"
            )
    return violations


def _evaluate_with_opa(rego_path, plan_path):
    """Use the real OPA engine if available. Returns (used_opa, violations)."""
    opa = shutil.which("opa")
    if not opa:
        return False, None
    try:
        out = subprocess.run(
            [opa, "eval", "-d", rego_path, "-i", plan_path,
             "--format", "json", "data.shiftleft.s3.deny"],
            capture_output=True, text=True, timeout=60, check=True,
        )
        parsed = json.loads(out.stdout)
        expressions = parsed.get("result", [{}])[0].get("expressions", [{}])
        value = expressions[0].get("value", []) if expressions else []
        return True, list(value)
    except (subprocess.SubprocessError, ValueError, KeyError, IndexError):
        # Fall back to the pure-Python evaluator on any OPA hiccup.
        return False, None


def run(plan_path, rego_path=None, alert=False, evidence_path=None):
    """Run the gate. Returns exit code (0 pass / 1 blocked)."""
    with open(plan_path, encoding="utf-8") as f:
        plan = json.load(f)

    used_opa, violations = (False, None)
    if rego_path and os.path.exists(rego_path):
        used_opa, violations = _evaluate_with_opa(rego_path, plan_path)
    if violations is None:
        violations = evaluate(plan)

    compliant = len(violations) == 0
    if evidence_path:
        evidence = {
            "check": "shiftleft.s3.tls",
            "engine": "opa" if used_opa else "python",
            "plan": os.path.basename(plan_path),
            "compliant": compliant,
            "violations": violations,
        }
        with open(evidence_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(evidence, f, indent=1)

    if compliant:
        # Pass is silent, like the demo.
        return 0
    for v in violations:
        print(f"BLOCKED: {v}")
    if alert:
        print("(alert mode: reporting only, not blocking)")
        return 0
    return 1


def main(argv):
    p = argparse.ArgumentParser(description="Shift-left S3 TLS policy gate")
    p.add_argument("plan", help="Path to terraform-plan JSON (or simplified resources JSON)")
    p.add_argument("--rego", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "policy", "s3_tls.rego"),
        help="Path to the .rego policy (used only if opa is on PATH)")
    p.add_argument("--alert", action="store_true",
                   help="Report violations but exit 0 (dev mode)")
    p.add_argument("--evidence", help="Write a JSON evidence record to this path")
    args = p.parse_args(argv[1:])
    return run(args.plan, rego_path=args.rego, alert=args.alert,
               evidence_path=args.evidence)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
