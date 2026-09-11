#!/usr/bin/env python3
"""Validate the Certification Package artifacts (CPO and example OCR) against
their official FedRAMP JSON schemas.

Separate from validate_sdr.py so the SDR gate stays focused. Exit code 1 on any
schema violation. A pass means the documents are well-formed, never that their
contents are true or that anyone is certified.

    python validation/scripts/validate_package.py
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")
COMMON = os.path.join(SCHEMA_DIR, "fedramp-common-definitions-schema-2026-06-24.json")

ARTIFACTS = [
    ("CPO", os.path.join(BASE, "package", "cpo", "cpo.json"),
     os.path.join(SCHEMA_DIR, "fedramp-certification-package-overview-schema-2026-06-24.json")),
    ("OCR", os.path.join(BASE, "package", "ocr", "ocr-example.json"),
     os.path.join(SCHEMA_DIR, "fedramp-ongoing-certification-report-schema-2026-06-24.json")),
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(doc, schema):
    import jsonschema
    from referencing import Registry, Resource

    common = load(COMMON)
    registry = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema)),
        (common["$id"], Resource.from_contents(common)),
    ])
    v = jsonschema.Draft202012Validator(schema, registry=registry)
    return ["/".join(str(p) for p in e.absolute_path) + ": " + e.message[:160]
            for e in v.iter_errors(doc)]


def main():
    total_errors = 0
    for label, doc_path, schema_path in ARTIFACTS:
        if not os.path.exists(doc_path):
            print(f"FAIL: {label} artifact missing at {os.path.relpath(doc_path, BASE)} "
                  "(run python sdr.py build)")
            total_errors += 1
            continue
        if not os.path.exists(schema_path):
            print(f"FAIL: {label} schema missing at {os.path.relpath(schema_path, BASE)}")
            total_errors += 1
            continue
        errors = validate(load(doc_path), load(schema_path))
        if errors:
            print(f"FAIL: {label} has {len(errors)} schema errors")
            for e in errors[:10]:
                print(f"    - {e}")
            total_errors += len(errors)
        else:
            print(f"PASS: {label} validates against its official FedRAMP schema")
    print(f"package validation: {total_errors} errors")
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
