#!/usr/bin/env python3
"""Offline tests for the Bucket B evidence-existence Config rule handler.

No AWS, no boto3: a fake S3 client stands in. Runs under pytest or directly:
    python automation/config-rules/test_evidence_existence_rule.py
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_existence_rule as rule  # noqa: E402

NOW = datetime.datetime(2026, 9, 7, tzinfo=datetime.timezone.utc)


class FakeS3Error(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self, last_modified=None, error=None):
        self._last_modified = last_modified
        self._error = error

    def head_object(self, **_kwargs):
        if self._error:
            raise self._error
        return {"LastModified": self._last_modified}


def test_present_and_fresh_is_compliant():
    s3 = FakeS3(last_modified=NOW - datetime.timedelta(days=10))
    r = rule.evaluate_evidence(s3, "b", "k", 365, now=NOW)
    assert r["compliance_type"] == "COMPLIANT"


def test_present_but_stale_is_noncompliant():
    s3 = FakeS3(last_modified=NOW - datetime.timedelta(days=400))
    r = rule.evaluate_evidence(s3, "b", "k", 365, now=NOW)
    assert r["compliance_type"] == "NON_COMPLIANT"
    assert "older than" in r["annotation"]


def test_missing_object_is_noncompliant():
    s3 = FakeS3(error=FakeS3Error("404"))
    r = rule.evaluate_evidence(s3, "b", "k", 365, now=NOW)
    assert r["compliance_type"] == "NON_COMPLIANT"
    assert "does not exist" in r["annotation"]


def test_no_location_is_not_applicable():
    r = rule.evaluate_evidence(FakeS3(), "", "", 365, now=NOW)
    assert r["compliance_type"] == "NOT_APPLICABLE"


def test_naive_timestamp_is_handled():
    naive = datetime.datetime(2026, 9, 1)  # no tzinfo
    s3 = FakeS3(last_modified=naive)
    r = rule.evaluate_evidence(s3, "b", "k", 365, now=NOW)
    assert r["compliance_type"] == "COMPLIANT"


def test_handler_never_emits_a_status_or_assessment():
    # The rule reports Config compliance only. It must not contain any code
    # path that writes an SDR implementation_status or assessment field.
    src = open(rule.__file__, encoding="utf-8").read()
    assert "implementation_status" not in src
    assert "put_assessment" not in src
    # It uses Config PutEvaluations (telemetry), which is expected.
    assert "put_evaluations" in src.lower()


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
