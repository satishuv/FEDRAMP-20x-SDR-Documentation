# Offline tests for the read-only posture collectors. No AWS account, no boto3
# required: a fake session returns canned client objects whose methods return
# canned responses or raise canned client errors. Run: python -m pytest, or
# python automation/collectors/test_collectors.py for a dependency-free run.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors  # noqa: E402


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    """Returns canned values per method name, or raises a canned error."""
    def __init__(self, responses=None, errors=None):
        self._responses = responses or {}
        self._errors = errors or {}

    def __getattr__(self, name):
        def method(**_kwargs):
            if name in self._errors:
                raise self._errors[name]
            return self._responses.get(name, {})
        return method


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, name):
        c = self._clients.get(name)
        if c is None:
            raise RuntimeError(f"no fake client for {name}")
        return c


def facts_by_check(facts):
    return {f["check"]: f for f in facts}


def test_security_hub_enabled_with_findings():
    sess = FakeSession({"securityhub": FakeClient(responses={
        "describe_hub": {"HubArn": "arn"},
        "get_findings": {"Findings": [{}, {}, {}], "NextToken": "more"},
    })})
    facts = collectors.collect_security_hub(sess, "us-east-1")
    by = facts_by_check(facts)
    assert by["enabled"]["status"] == "ENABLED"
    assert "3+" in by["failed_findings"]["detail"]


def test_security_hub_not_enabled():
    sess = FakeSession({"securityhub": FakeClient(
        errors={"describe_hub": FakeClientError("InvalidAccessException")})})
    facts = collectors.collect_security_hub(sess, "us-east-1")
    assert facts_by_check(facts)["enabled"]["status"] == "NOT_ENABLED"


def test_access_analyzer_none():
    sess = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": []}})})
    facts = collectors.collect_access_analyzer(sess, "us-east-1")
    assert facts_by_check(facts)["analyzer"]["status"] == "NONE"


def test_access_analyzer_present_with_findings():
    sess = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": [{"arn": "a1"}]},
        "list_findings": {"findings": [{}, {}]},
    })})
    facts = facts_by_check(collectors.collect_access_analyzer(sess, "us-east-1"))
    assert facts["analyzer"]["status"] == "PRESENT"
    assert "2 active" in facts["active_findings"]["detail"]


def test_inspector_active():
    sess = FakeSession({"inspector2": FakeClient(responses={
        "list_coverage": {"coveredResources": [
            {"scanStatus": {"statusCode": "ACTIVE"}},
            {"scanStatus": {"statusCode": "INACTIVE"}},
        ]}})})
    fact = collectors.collect_inspector(sess, "us-east-1")[0]
    assert fact["status"] == "ACTIVE"
    assert "1 actively scanned of 2" in fact["detail"]


def test_guardduty_enabled():
    sess = FakeSession({"guardduty": FakeClient(responses={
        "list_detectors": {"DetectorIds": ["d1"]},
        "get_detector": {"Status": "ENABLED"},
    })})
    assert collectors.collect_guardduty(sess, "us-east-1")[0]["status"] == "ENABLED"


def test_guardduty_none():
    sess = FakeSession({"guardduty": FakeClient(responses={
        "list_detectors": {"DetectorIds": []}})})
    assert collectors.collect_guardduty(sess, "us-east-1")[0]["status"] == "NONE"


def test_backup_present_and_protected():
    sess = FakeSession({"backup": FakeClient(responses={
        "list_backup_plans": {"BackupPlansList": [{}]},
        "list_protected_resources": {"Results": [{}, {}, {}]},
    })})
    by = facts_by_check(collectors.collect_backup(sess, "us-east-1"))
    assert by["plans"]["status"] == "PRESENT"
    assert "3 protected" in by["protected_resources"]["detail"]


def test_kms_rotation_fraction():
    kms = FakeClient(responses={
        "list_keys": {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]},
        "get_key_rotation_status": {"KeyRotationEnabled": True},
    })
    sess = FakeSession({"kms": kms})
    fact = collectors.collect_kms(sess, "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2" in fact["detail"]


def test_one_service_failure_does_not_raise():
    # A client that raises on every call must yield an ERROR fact, not crash.
    sess = FakeSession({"guardduty": FakeClient(
        errors={"list_detectors": FakeClientError("AccessDenied")})})
    facts = collectors.collect_guardduty(sess, "us-east-1")
    assert facts and facts[0]["status"].startswith("ERROR")


def test_allowlist_is_read_only():
    # Every action in the allowlist must be a read verb; no mutations ever.
    read_prefixes = ("Get", "List", "Describe")
    for action in collectors.READ_ONLY_ACTIONS:
        verb = action.split(":", 1)[1]
        assert verb.startswith(read_prefixes), f"non-read action in allowlist: {action}"


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
