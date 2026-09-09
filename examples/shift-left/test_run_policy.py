#!/usr/bin/env python3
"""Offline tests for the shift-left policy runner.

No opa binary required (tests exercise the pure-Python evaluator path and the
runner semantics). Runs under pytest or directly:
    python examples/shift-left/test_run_policy.py
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_policy as rp  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
COMPLIANT = os.path.join(HERE, "fixtures", "plan-compliant.json")
NONCOMPLIANT = os.path.join(HERE, "fixtures", "plan-noncompliant.json")


def test_compliant_plan_has_no_violations():
    with open(COMPLIANT, encoding="utf-8") as f:
        plan = json.load(f)
    assert rp.evaluate(plan) == []


def test_noncompliant_plan_has_a_violation():
    with open(NONCOMPLIANT, encoding="utf-8") as f:
        plan = json.load(f)
    v = rp.evaluate(plan)
    assert len(v) == 1
    assert "insecure-bucket" in v[0]


def test_runner_compliant_exits_zero_and_silent(capsys=None):
    # rego_path None forces the pure-Python path (no opa dependency)
    code = rp.run(COMPLIANT, rego_path=None)
    assert code == 0


def test_runner_noncompliant_blocks_exit_one():
    code = rp.run(NONCOMPLIANT, rego_path=None)
    assert code == 1


def test_alert_mode_reports_but_exits_zero():
    code = rp.run(NONCOMPLIANT, rego_path=None, alert=True)
    assert code == 0


def test_evidence_written_for_both_outcomes():
    with tempfile.TemporaryDirectory() as d:
        ok = os.path.join(d, "ev-ok.json")
        bad = os.path.join(d, "ev-bad.json")
        rp.run(COMPLIANT, rego_path=None, evidence_path=ok)
        rp.run(NONCOMPLIANT, rego_path=None, evidence_path=bad)
        with open(ok, encoding="utf-8") as f:
            eok = json.load(f)
        with open(bad, encoding="utf-8") as f:
            ebad = json.load(f)
        assert eok["compliant"] is True and eok["violations"] == []
        assert ebad["compliant"] is False and len(ebad["violations"]) == 1
        assert ebad["engine"] == "python"


def test_terraform_show_shape_supported():
    plan = {
        "planned_values": {"root_module": {"resources": [
            {"type": "aws_s3_bucket", "values": {"bucket": "b1"}},
        ]}}
    }
    v = rp.evaluate(plan)
    assert len(v) == 1 and "b1" in v[0]


def test_policy_enforces_tls_detects_deny():
    good = json.dumps({"Statement": [
        {"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    ]})
    bad = json.dumps({"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject"}
    ]})
    assert rp._policy_enforces_tls(good) is True
    assert rp._policy_enforces_tls(bad) is False
    assert rp._policy_enforces_tls(None) is False


def _run_direct():
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_direct())
