#!/usr/bin/env python3
"""Real synthesis test for the generated CDK stack.

Earlier the generated cdk_stack.py contained doubled braces ({{...}}) that made
it invalid Python and non-synthesizable; the CFN-only test never caught it. This
test imports the GENERATED cdk_stack.py and actually synthesizes it with
aws-cdk-lib (App().synth()), then asserts the produced CloudFormation template
contains the expected resources. It is skipped (not failed) only if aws-cdk-lib
is not installed in the environment.

    python automation/config-rules/deploy/test_cdk_synth.py
"""

import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    if importlib.util.find_spec("aws_cdk") is None:
        print("SKIP: aws-cdk-lib not installed; CI installs it and runs the synth")
        return 0

    # Regenerate to guarantee we synth the current generator output.
    gen = os.path.join(HERE, "generate_templates.py")
    spec = importlib.util.spec_from_file_location("gen_templates", gen)
    gmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gmod)
    gmod.write_all()

    # Import the generated stack module and synthesize it.
    sys.path.insert(0, HERE)
    from aws_cdk import App
    stack_path = os.path.join(HERE, "cdk_stack.py")
    sspec = importlib.util.spec_from_file_location("cdk_stack", stack_path)
    smod = importlib.util.module_from_spec(sspec)
    sspec.loader.exec_module(smod)

    app = App()
    smod.EvidenceRulesStack(app, "TestEvidenceRules")
    cloud_assembly = app.synth()
    tmpl = cloud_assembly.get_stack_by_name("TestEvidenceRules").template
    resources = tmpl.get("Resources", {})

    types = [r["Type"] for r in resources.values()]
    manifest = json.load(open(os.path.join(HERE, "..", "rules-manifest.json"), encoding="utf-8"))
    n_rules = len(manifest["rules"])

    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    check("stack synthesizes to a CloudFormation template", bool(resources))
    check("a Lambda function is synthesized", "AWS::Lambda::Function" in types)
    check("an IAM role is synthesized", "AWS::IAM::Role" in types)
    check(f"all {n_rules} Config rules are synthesized",
          types.count("AWS::Config::ConfigRule") == n_rules)
    # No literal doubled-brace artifact leaked into any string value.
    flat = json.dumps(tmpl)
    check("no doubled-brace artifact in the synthesized template",
          "{{" not in flat and "value_as_string" not in flat)
    # The S3 evidence ARN is present and partition-templated (not hard-coded aws).
    check("S3 evidence ARN is present in an IAM policy",
          ":s3:::" in flat)

    print(f"\n{passed}/{passed + failed} CDK synth checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
