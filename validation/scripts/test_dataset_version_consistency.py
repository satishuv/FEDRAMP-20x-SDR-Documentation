# Dataset-version consistency test for curated data files.
#
# Finding: automation/collectors/pending-ksi-classification.json and
# automation/config-rules/rules-manifest.json hardcoded the OLD dataset version
# 2026.07.14.01 while the canonical pin advanced to 2026.09.13.02. These are
# curated data files (not build-generated), so nothing forced them current.
# This test pins their dataset_version to the canonical pinned dataset so the
# drift is caught in CI instead of read by a human.
#
# The canonical version is the pinned dataset's info.version (the same value
# validate_sdr.py's dataset_version_agreement trusts).
#
# Run: python validation/scripts/test_dataset_version_consistency.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Curated data files that declare a dataset_version and must track the pin.
CURATED = [
    os.path.join("automation", "collectors", "pending-ksi-classification.json"),
    os.path.join("automation", "config-rules", "rules-manifest.json"),
]

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def canonical_version():
    ds = json.load(open(os.path.join(BASE, "references",
                                     "fedramp-consolidated-rules.json"), encoding="utf-8"))
    return ds.get("info", {}).get("version")


def _declared(path):
    d = json.load(open(os.path.join(BASE, path), encoding="utf-8"))
    return (d.get("meta", {}) or {}).get("dataset_version") or d.get("dataset_version")


def main():
    pin = canonical_version()
    check("canonical pinned dataset version resolves", bool(pin))
    for rel in CURATED:
        got = _declared(rel)
        check(f"{rel} dataset_version == {pin} (got {got})", got == pin)
    print(f"\n{'PASS' if not _fail else 'FAIL'}: dataset-version consistency "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
