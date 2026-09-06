# Offline tests for the deterministic fact-to-field pre-fill. No AWS account
# and no files needed: the prefill_ksi function is exercised directly with
# synthetic registry entries, facts, and records. Run:
#   python automation/prefill/test_prefill.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prefill_from_facts as pf  # noqa: E402


def blank_ksi_record():
    return {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD: Information has not been provided."],
        "validation": ["TBD: Information has not been provided."],
        "assessment": ["TBD: Independent assessment has not been performed."],
        "tests": [],
        "evidence": [],
        "extension": {
            "automation_verification": "TBD: Information has not been provided.",
            "owner": "TBD: Information has not been provided.",
        },
    }


def test_is_tbd():
    assert pf.is_tbd([])
    assert pf.is_tbd(["TBD: Information has not been provided."])
    assert pf.is_tbd("")
    assert not pf.is_tbd(["Real content here."])
    assert not pf.is_tbd("A real sentence.")


def test_config_fact_prefills_tests_and_evidence():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "cloudtrail-enabled",
                    "source": "verify", "check_id": "KSI-CMT-LMC:verify:config:cloudtrail-enabled"}],
    }
    config_by_rule = {"cloudtrail-enabled": {
        "rule": "cloudtrail-enabled", "compliance_type": "COMPLIANT",
        "collected_at": "2026-09-06T00:00:00+00:00", "region": "us-east-1"}}
    rec = blank_ksi_record()
    changed, notes = pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, {})
    assert changed
    assert len(rec["tests"]) == 1 and "cloudtrail-enabled" in rec["tests"][0]
    assert len(rec["evidence"]) == 1
    assert "COMPLIANT" in rec["tests"][0]


def test_posture_fact_prefills():
    ksi_entry = {"services": ["Amazon GuardDuty"], "checks": []}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ENABLED", "detail": "Detector status ENABLED",
                              "collected_at": "2026-09-06T00:00:00+00:00",
                              "region": "us-east-1"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-INR-XXX", rec, ksi_entry, {}, posture)
    assert changed
    assert any("guardduty.detector = ENABLED" in t for t in rec["tests"])


def test_never_touches_status_or_assessment():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "COMPLIANT",
                            "collected_at": "2026-09-06T00:00:00+00:00", "region": "x"}}
    rec = blank_ksi_record()
    pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, {})
    assert rec["implementation_status"] == "Not Implemented"
    assert rec["assessment"] == ["TBD: Independent assessment has not been performed."]


def test_does_not_overwrite_populated_fields():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "COMPLIANT",
                            "collected_at": "2026-09-06T00:00:00+00:00", "region": "x"}}
    rec = blank_ksi_record()
    rec["tests"] = ["Real author-written test, do not clobber."]
    changed, _ = pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, {})
    # evidence and automation_verification still fill, but tests is preserved.
    assert rec["tests"] == ["Real author-written test, do not clobber."]


def test_error_and_not_deployed_facts_do_not_prefill():
    ksi_entry = {
        "services": ["AWS Config", "Amazon GuardDuty"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "RULE_NOT_DEPLOYED",
                            "collected_at": "t", "region": "x"}}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ERROR:AccessDenied", "detail": "d",
                              "collected_at": "t", "region": "x"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, posture)
    assert not changed
    assert rec["tests"] == []


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
