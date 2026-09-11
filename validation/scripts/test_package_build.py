#!/usr/bin/env python3
"""Offline test: the CPO and OCR generators produce schema-valid documents.

Builds both artifacts in-process from the current offering profile and
validates each against its official FedRAMP schema. No network, no AWS.

    python validation/scripts/test_package_build.py
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")

import build_cpo  # noqa: E402
import build_ocr  # noqa: E402


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _validate(doc, schema_name):
    import jsonschema
    from referencing import Registry, Resource
    schema = _load(os.path.join(SCHEMA_DIR, schema_name))
    common = _load(os.path.join(SCHEMA_DIR, "fedramp-common-definitions-schema-2026-06-24.json"))
    reg = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema)),
        (common["$id"], Resource.from_contents(common)),
    ])
    v = jsonschema.Draft202012Validator(schema, registry=reg)
    return list(v.iter_errors(doc))


def test_cpo_is_schema_valid():
    profile = _load(build_cpo.PROFILE)
    doc = build_cpo.build_cpo(profile)
    errs = _validate(doc, "fedramp-certification-package-overview-schema-2026-06-24.json")
    assert not errs, f"CPO schema errors: {[e.message for e in errs[:3]]}"


def test_ocr_is_schema_valid():
    profile = _load(build_ocr.PROFILE)
    doc = build_ocr.build_ocr(profile)
    errs = _validate(doc, "fedramp-ongoing-certification-report-schema-2026-06-24.json")
    assert not errs, f"OCR schema errors: {[e.message for e in errs[:3]]}"


def test_ocr_empty_incidents_attests_none():
    profile = _load(build_ocr.PROFILE)
    doc = build_ocr.build_ocr(profile)
    # An empty incidents array is the schema-intended attestation of none.
    assert doc["reportableIncidents"]["incidents"] == []


def test_ocr_period_is_deterministic():
    # Two builds from the same pinned dataset yield the same report period.
    profile = _load(build_ocr.PROFILE)
    a = build_ocr.build_ocr(profile)["reportPeriod"]
    b = build_ocr.build_ocr(profile)["reportPeriod"]
    assert a == b


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
