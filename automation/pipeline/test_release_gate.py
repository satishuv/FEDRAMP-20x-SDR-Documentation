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

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.join(HERE, "sdr-pipeline.yaml")
BUILDSPEC = os.path.join(HERE, "buildspec-validate.yml")


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

    print(f"\n{passed}/{passed + failed} release-gate checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
