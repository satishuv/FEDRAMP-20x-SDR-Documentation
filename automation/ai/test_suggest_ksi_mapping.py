"""Offline tests for the OPT-IN AI architecture-to-KSI suggester. Advisory,
read-only, no write path. Uses the repo's own KSI-service map.

Run: python automation/ai/test_suggest_ksi_mapping.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import suggest_ksi_mapping as sk  # noqa: E402

# A tiny synthetic KSI map so the test does not depend on the full dataset.
FAKE_MAP = {
    "meta": {"count": 2},
    "ksis": {
        "KSI-CMT-LMC": {"aws_implementation": "Turn on AWS CloudTrail and AWS Config.",
                        "verify_method": "", "validate_method": ""},
        "KSI-SVC-SIN": {"aws_implementation": "Encrypt data in Amazon S3 with AWS KMS.",
                        "verify_method": "", "validate_method": ""},
    },
}


def test_suggests_ksis_for_matching_services():
    out = sk.suggest_from_services(["AWS CloudTrail", "Amazon S3"], FAKE_MAP)
    assert "KSI-CMT-LMC" in out["AWS CloudTrail"]
    assert "KSI-SVC-SIN" in out["Amazon S3"]
    print("PASS: test_suggests_ksis_for_matching_services")


def test_unmatched_service_gets_empty_list():
    out = sk.suggest_from_services(["Amazon Braket"], FAKE_MAP)
    assert out["Amazon Braket"] == []
    print("PASS: test_unmatched_service_gets_empty_list")


def test_matching_is_case_insensitive():
    out = sk.suggest_from_services(["aws cloudtrail"], FAKE_MAP)
    assert "KSI-CMT-LMC" in out["aws cloudtrail"]
    print("PASS: test_matching_is_case_insensitive")


def test_module_has_no_write_path():
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "suggest_ksi_mapping.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert '"w"' not in src and "'w'" not in src, "suggester must not write files"
    assert "records-store" not in src, "suggester must not touch the record store"
    print("PASS: test_module_has_no_write_path")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
