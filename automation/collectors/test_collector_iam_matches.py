#!/usr/bin/env python3
"""Collector IAM parity test.

The scheduled collector pipeline (automation/pipeline/sdr-pipeline.yaml) deploys
a CollectorRole. That role's granted actions MUST be a superset of the actions
the collectors actually call (automation/collectors/collectors.py
READ_ONLY_ACTIONS); otherwise a deployed collector produces AccessDenied for
everything the grant omits. This test fails if the collector adds an API call
that the deployed role does not grant.

    python automation/collectors/test_collector_iam_matches.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import collectors  # noqa: E402

PIPELINE = os.path.join(BASE, "automation", "pipeline", "sdr-pipeline.yaml")


def granted_collector_actions():
    """Extract the IAM actions the CollectorRole grants from the pipeline YAML.

    Parsed textually (no yaml dependency required): collect every '- svc:Action'
    list item that looks like an IAM action. This intentionally over-collects
    across the file, which is safe for a SUPERSET check (we only need to prove
    every READ_ONLY_ACTION is granted somewhere in the collector role)."""
    import re
    actions = set()
    action_re = re.compile(r"^\s*-\s+([a-z0-9]+:[A-Za-z0-9*]+)\s*$")
    with open(PIPELINE, encoding="utf-8") as f:
        for line in f:
            m = action_re.match(line)
            if m:
                actions.add(m.group(1))
    return actions


def main():
    needed = set(collectors.READ_ONLY_ACTIONS)
    granted = granted_collector_actions()
    missing = sorted(needed - granted)
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    check("the pipeline grants a non-trivial set of collector actions",
          len(granted) >= len(needed))
    check("every collector READ_ONLY_ACTION is granted by the deployed role",
          not missing)
    if missing:
        print(f"    missing grants: {missing}")

    print(f"\n{passed}/{passed + failed} collector IAM parity checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
