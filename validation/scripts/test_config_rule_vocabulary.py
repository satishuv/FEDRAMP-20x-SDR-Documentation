# Config-rule vocabulary gate test.
#
# Finding: the registry generator extracted every backtick token from guidance
# prose as an AWS Config managed rule. "aurora" (not a real managed rule; AWS
# has specific rules such as rds-cluster-multi-az-enabled) leaked in this way.
# The generator now rejects any extracted token not on the pinned allowlist
# automation/config-rules/known-config-managed-rules.json, and "aurora" is gone.
#
# Run: python validation/scripts/test_config_rule_vocabulary.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import build_collector_registry as bcr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def main():
    known = bcr.load_known_config_rules()
    check("allowlist loads and is non-empty", len(known) >= 30)
    check("allowlist does NOT contain the bogus 'aurora'", "aurora" not in known)
    check("allowlist contains the real rules aurora was standing in for",
          {"rds-multi-az-support", "elb-cross-zone-load-balancing-enabled"} <= known)

    # Every config_managed_rule target in the generated registry is on the
    # allowlist (the fail-closed gate guarantees this at build time).
    reg = json.load(open(os.path.join(BASE, "automation", "collectors", "registry.json"),
                         encoding="utf-8"))
    targets = {c["target"] for k in reg["ksis"].values() for c in k["checks"]
               if c.get("type") == "config_managed_rule"}
    off_list = targets - known
    check("no registry config-rule target is outside the allowlist",
          not off_list)
    check("aurora is not a rule target in the registry", "aurora" not in targets)

    print(f"\n{'PASS' if not _fail else 'FAIL'}: config-rule vocabulary "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
