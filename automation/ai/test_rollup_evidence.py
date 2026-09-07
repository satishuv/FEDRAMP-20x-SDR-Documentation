"""Offline tests for the OPT-IN AI evidence rollup. Summarizes existing facts;
never claims compliance; never writes the record store. Deterministic, offline.

Run: python automation/ai/test_rollup_evidence.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollup_evidence as re_  # noqa: E402


def fact(service, check, status, detail):
    return {"service": service, "check": check, "status": status,
            "detail": detail, "region": "us-east-1",
            "collected_at": "2026-09-07T00:00:00+00:00"}


def test_rollup_summarizes_given_facts():
    text = re_.TemplateRoller().rollup("KSI-X", [
        fact("config", "recorder", "RECORDING", "1 of 1 recording"),
        fact("kms", "key_rotation", "OBSERVED", "5 of 6 keys rotating")])
    assert "config.recorder" in text and "kms.key_rotation" in text
    assert "1 of 1 recording" in text
    print("PASS: test_rollup_summarizes_given_facts")


def test_rollup_never_claims_compliance():
    text = re_.TemplateRoller().rollup("KSI-X", [
        fact("config", "recorder", "RECORDING", "1 of 1 recording")])
    assert "not a determination" in text.lower()
    print("PASS: test_rollup_never_claims_compliance")


def test_rollup_invents_no_new_facts():
    # Every service/check/detail in the output must have come from the input.
    facts = [fact("s3", "public_access_block", "OBSERVED", "33 of 33 blocked")]
    text = re_.TemplateRoller().rollup("KSI-X", facts)
    assert "s3.public_access_block" in text and "33 of 33 blocked" in text
    # No other service name should appear.
    for other in ("guardduty", "cloudtrail", "iam"):
        assert other not in text
    print("PASS: test_rollup_invents_no_new_facts")


def test_empty_facts_yields_no_summary():
    assert re_.TemplateRoller().rollup("KSI-X", []) is None
    print("PASS: test_empty_facts_yields_no_summary")


def test_module_does_not_write_record_store():
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "rollup_evidence.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert "records-store.json" not in src, "rollup must not touch the record store"
    print("PASS: test_module_does_not_write_record_store")


def test_offline_roller_needs_no_backend():
    r = re_.get_roller("template")
    assert r.name == "template"
    print("PASS: test_offline_roller_needs_no_backend")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
