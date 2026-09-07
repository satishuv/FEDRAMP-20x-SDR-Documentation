"""Offline tests for the OPT-IN AI finding explainer. Advisory-only, read-only,
no write path. Deterministic TemplateExplainer, no model, no network.

Run: python automation/ai/test_explain_findings.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import explain_findings as ef  # noqa: E402


def fact(service, check, status, detail):
    return {"service": service, "check": check, "status": status,
            "detail": detail, "region": "us-east-1",
            "collected_at": "2026-09-07T00:00:00+00:00"}


def test_notable_detection():
    assert ef.is_notable(fact("config", "rule_compliance", "OBSERVED",
                              "3 compliant, 4 non-compliant of 25"))
    assert ef.is_notable(fact("iam", "password_policy", "NONE", "No policy"))
    assert not ef.is_notable(fact("guardduty", "detector", "ENABLED",
                                  "Detector status ENABLED"))
    print("PASS: test_notable_detection")


def test_explains_known_finding_with_remediation():
    text = ef.TemplateExplainer().explain(
        fact("config", "rule_compliance", "OBSERVED",
             "3 compliant, 4 non-compliant of 25"))
    assert "non-compliant" in text.lower()
    assert "remediate" in text.lower() or "review" in text.lower()
    print("PASS: test_explains_known_finding_with_remediation")


def test_explanation_never_concludes_compliance():
    text = ef.TemplateExplainer().explain(
        fact("iam", "password_policy", "NONE", "No account password policy set"))
    assert "not a compliance determination" in text.lower()
    print("PASS: test_explanation_never_concludes_compliance")


def test_unknown_finding_still_gets_safe_generic_guidance():
    text = ef.TemplateExplainer().explain(
        fact("someservice", "somecheck", "NONE", "whatever"))
    assert "review" in text.lower()
    assert "not a compliance determination" in text.lower()
    print("PASS: test_unknown_finding_still_gets_safe_generic_guidance")


def test_module_has_no_write_path():
    # Static guard: the explainer module must not open files for writing or
    # touch the record store. Assert its source contains no write mode / record
    # store reference.
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "explain_findings.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert "records-store" not in src, "explainer must not reference the record store"
    assert 'open(' not in src or '"w"' not in src, "explainer must not open files for writing"
    assert "SIDECAR" not in src, "explainer must not write a sidecar"
    print("PASS: test_module_has_no_write_path")


def test_offline_explainer_needs_no_backend():
    e = ef.get_explainer("template")
    assert e.name == "template"
    assert isinstance(e.explain(fact("kms", "key_rotation", "OBSERVED",
                                     "5 of 6 keys rotating")), str)
    print("PASS: test_offline_explainer_needs_no_backend")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
