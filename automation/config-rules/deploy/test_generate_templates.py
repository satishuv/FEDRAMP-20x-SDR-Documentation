#!/usr/bin/env python3
"""Offline tests for generate_templates.py. No AWS, no CDK install needed:
we test the CloudFormation dict the generator builds from the manifest.

Run: python automation/config-rules/deploy/test_generate_templates.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate_templates as gt  # noqa: E402


def _manifest():
    return gt.load_manifest()


def _cfn():
    return gt.build_cfn(_manifest())


def test_exactly_11_config_rules():
    cfn = _cfn()
    rules = [k for k, v in cfn["Resources"].items()
             if v["Type"] == "AWS::Config::ConfigRule"]
    assert len(rules) == 11, f"expected 11 ConfigRules, got {len(rules)}"


def test_rule_names_match_manifest():
    cfn = _cfn()
    manifest = _manifest()
    got = {v["Properties"]["ConfigRuleName"]
           for v in cfn["Resources"].values()
           if v["Type"] == "AWS::Config::ConfigRule"}
    expected = {r["rule_name"] for r in manifest["rules"]}
    assert got == expected


def test_max_age_days_match_manifest():
    cfn = _cfn()
    manifest = _manifest()
    by_name = {v["Properties"]["ConfigRuleName"]: v["Properties"]
               for v in cfn["Resources"].values()
               if v["Type"] == "AWS::Config::ConfigRule"}
    for r in manifest["rules"]:
        got = by_name[r["rule_name"]]["InputParameters"]["max_age_days"]
        assert got == r["default_max_age_days"], \
            f"{r['rule_name']}: {got} != {r['default_max_age_days']}"


def test_lambda_role_and_permission_exist():
    res = _cfn()["Resources"]
    types = {v["Type"] for v in res.values()}
    assert "AWS::Lambda::Function" in types
    assert "AWS::IAM::Role" in types
    assert "AWS::Lambda::Permission" in types
    # The permission must grant config.amazonaws.com invoke.
    perm = next(v for v in res.values()
                if v["Type"] == "AWS::Lambda::Permission")
    assert perm["Properties"]["Principal"] == "config.amazonaws.com"


def test_role_is_readonly_on_evidence():
    res = _cfn()["Resources"]
    role = next(v for v in res.values() if v["Type"] == "AWS::IAM::Role")
    stmts = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    s3_actions = set()
    for s in stmts:
        act = s["Action"]
        for a in (act if isinstance(act, list) else [act]):
            if a.startswith("s3:"):
                s3_actions.add(a)
    # Only read verbs on the evidence bucket.
    assert s3_actions <= {"s3:GetObject", "s3:GetObjectTagging"}, \
        f"unexpected s3 write action: {s3_actions}"


def test_handler_is_the_shared_evaluator():
    res = _cfn()["Resources"]
    fn = next(v for v in res.values() if v["Type"] == "AWS::Lambda::Function")
    assert fn["Properties"]["Handler"] == _manifest()["meta"]["handler"]


def test_deterministic_build():
    a = json.dumps(_cfn(), sort_keys=True)
    b = json.dumps(_cfn(), sort_keys=True)
    assert a == b


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
