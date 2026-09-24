# Tests for the customer custom-Config-rule overlay (Max's importer feature).
# Verifies the overlay loader parses entries, and that injected custom rules
# appear as collectable config_managed_rule checks. Uses an isolated overlay
# path and restores the registry so no tracked file is left mutated.
#
#   python validation/scripts/test_customer_config_rules.py

import json
import os
import subprocess
import sys
import tempfile

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


def test_loader_parses_string_and_object_entries():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "customer-config-rules.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"KSI-CNA-MAT": ["my-ingress-check",
                                   {"rule_name": "my-egress-check",
                                    "description": "egress"}]}, f)
    orig = bcr.CUSTOMER_RULES_FILE
    bcr.CUSTOMER_RULES_FILE = p
    try:
        got = bcr.load_customer_rules()
    finally:
        bcr.CUSTOMER_RULES_FILE = orig
    entries = got.get("KSI-CNA-MAT", [])
    check("both entries parsed", len(entries) == 2)
    check("string entry normalized to rule_name",
          any(e["rule_name"] == "my-ingress-check" for e in entries))
    check("object entry preserved",
          any(e.get("description") == "egress" for e in entries))


def test_missing_overlay_is_empty():
    orig = bcr.CUSTOMER_RULES_FILE
    bcr.CUSTOMER_RULES_FILE = os.path.join(tempfile.mkdtemp(), "nope.json")
    try:
        check("absent overlay -> empty dict", bcr.load_customer_rules() == {})
    finally:
        bcr.CUSTOMER_RULES_FILE = orig


def test_malformed_overlay_is_ignored_not_fatal():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "customer-config-rules.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{ not valid json")
    orig = bcr.CUSTOMER_RULES_FILE
    bcr.CUSTOMER_RULES_FILE = p
    try:
        check("malformed overlay -> empty dict (no crash)",
              bcr.load_customer_rules() == {})
    finally:
        bcr.CUSTOMER_RULES_FILE = orig


def test_injected_custom_rule_appears_and_restores_clean():
    overlay = bcr.CUSTOMER_RULES_FILE
    registry_path = os.path.join(BASE, "automation", "collectors", "registry.json")
    before = open(registry_path, encoding="utf-8").read()
    existed = os.path.exists(overlay)
    build = os.path.join(BASE, "validation", "scripts", "build_collector_registry.py")
    try:
        with open(overlay, "w", encoding="utf-8") as f:
            json.dump({"KSI-CNA-MAT": [{"rule_name": "acme-custom-ingress",
                                        "description": "custom"}]}, f)
        subprocess.run([sys.executable, build], cwd=BASE,
                       capture_output=True, text=True)
        reg = json.load(open(registry_path, encoding="utf-8"))
        targets = [c.get("target") for c in reg["ksis"]["KSI-CNA-MAT"]["checks"]]
        check("custom rule injected as a check", "acme-custom-ingress" in targets)
        custom = [c for c in reg["ksis"]["KSI-CNA-MAT"]["checks"]
                  if c.get("target") == "acme-custom-ingress"]
        check("custom check is collectable_now and marked custom",
              bool(custom) and custom[0].get("collectable_now")
              and custom[0].get("custom"))
    finally:
        if not existed and os.path.exists(overlay):
            os.remove(overlay)
        subprocess.run([sys.executable, build], cwd=BASE,
                       capture_output=True, text=True)
    after = open(registry_path, encoding="utf-8").read()
    check("registry restored byte-for-byte after overlay removed", before == after)


def main():
    for t in (test_loader_parses_string_and_object_entries,
              test_missing_overlay_is_empty,
              test_malformed_overlay_is_ignored_not_fatal,
              test_injected_custom_rule_appears_and_restores_clean):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: customer config rules ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
