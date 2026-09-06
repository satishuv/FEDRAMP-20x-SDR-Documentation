# Scale and fault-injection tests for the read-only posture collectors.
#
# This is the rung that answers "what if there are hundreds of services and it
# crashes": it fires large synthetic API responses and every failure mode
# through the collectors with NO AWS account, and asserts three invariants for
# each collector under every condition:
#   1. It never raises (a single service failure yields an ERROR fact, per the
#      module contract), so one bad service cannot sink a whole run.
#   2. It always returns at least one fact.
#   3. Its output size is bounded (it summarizes counts, it does not echo every
#      finding), so a 10,000-finding account does not blow up the facts store.
#
# Run: python automation/collectors/test_collectors_scale.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors  # noqa: E402


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class ScriptedClient:
    """Returns canned values per method, or raises a canned error per method."""
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


# Every error mode a real AWS API throws that a collector must survive.
FAULT_MODES = {
    "throttling": FakeClientError("ThrottlingException"),
    "access_denied": FakeClientError("AccessDeniedException"),
    "not_found": FakeClientError("ResourceNotFoundException"),
    "timeout": TimeoutError("read timed out"),
    "generic": RuntimeError("boom"),
    "malformed": KeyError("unexpected shape"),
}

# The (collector, per-service client name, list of methods it calls) map, so a
# fault can be injected on each call site.
COLLECTOR_CALLS = {
    "security_hub": ("securityhub", ["describe_hub", "get_findings"]),
    "access_analyzer": ("accessanalyzer", ["list_analyzers", "list_findings"]),
    "inspector": ("inspector2", ["list_coverage"]),
    "guardduty": ("guardduty", ["list_detectors", "get_detector"]),
    "backup": ("backup", ["list_backup_plans", "list_protected_resources"]),
    "kms": ("kms", ["list_keys", "get_key_rotation_status"]),
    "config": ("config", ["describe_configuration_recorder_status",
                          "get_discovered_resource_counts",
                          "describe_compliance_by_config_rule"]),
    "cloudtrail": ("cloudtrail", ["describe_trails", "get_trail_status"]),
    "s3": ("s3", ["list_buckets", "get_public_access_block"]),
    "iam": ("iam", ["get_account_summary", "get_account_password_policy"]),
}

COLLECTOR_FN = dict(collectors.COLLECTORS)


def _big_ok_responses(client_name, n):
    """Large but well-formed responses so we exercise the count/summarize path
    at scale rather than an error path."""
    findings = [{"Id": f"f{i}"} for i in range(n)]
    return {
        "securityhub": {"describe_hub": {"HubArn": "arn"},
                        "get_findings": {"Findings": findings[:100], "NextToken": "more"}},
        "accessanalyzer": {"list_analyzers": {"analyzers": [{"arn": "a1"}]},
                           "list_findings": {"findings": findings}},
        "inspector2": {"list_coverage": {"coveredResources": [
            {"scanStatus": {"statusCode": "ACTIVE"}} for _ in range(n)]}},
        "guardduty": {"list_detectors": {"DetectorIds": ["d1"]},
                      "get_detector": {"Status": "ENABLED"}},
        "backup": {"list_backup_plans": {"BackupPlansList": [{} for _ in range(n)]},
                   "list_protected_resources": {"Results": [{} for _ in range(n)]}},
        "kms": {"list_keys": {"Keys": [{"KeyId": f"k{i}"} for i in range(n)]},
                "get_key_rotation_status": {"KeyRotationEnabled": True}},
        "config": {
            "describe_configuration_recorder_status": {
                "ConfigurationRecordersStatus": [{"recording": True} for _ in range(n)]},
            "get_discovered_resource_counts": {
                "resourceCounts": [{"resourceType": f"AWS::Svc::R{i}", "count": i}
                                   for i in range(n)]},
            "describe_compliance_by_config_rule": {
                "ComplianceByConfigRules": [
                    {"Compliance": {"ComplianceType": "COMPLIANT"}} for _ in range(n)]}},
        "cloudtrail": {
            "describe_trails": {"trailList": [
                {"Name": f"t{i}", "TrailARN": f"arn:t{i}", "IsMultiRegionTrail": True}
                for i in range(n)]},
            "get_trail_status": {"IsLogging": True}},
        "s3": {"list_buckets": {"Buckets": [{"Name": f"b{i}"} for i in range(n)]},
               "get_public_access_block": {"PublicAccessBlockConfiguration": {
                   "BlockPublicAcls": True, "IgnorePublicAcls": True,
                   "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}},
        "iam": {"get_account_summary": {"SummaryMap": {"Users": n, "MFADevices": n,
                                                       "Roles": n}},
                "get_account_password_policy": {"PasswordPolicy": {}}},
    }[client_name]


def _assert_invariants(name, facts):
    assert isinstance(facts, list), f"{name}: did not return a list"
    assert len(facts) >= 1, f"{name}: returned no fact"
    for f in facts:
        assert set(("service", "check", "status", "detail", "region",
                    "collected_at")).issubset(f), f"{name}: malformed fact {f}"
        # Bounded output: the detail is a short summary, never a dump of N items.
        assert len(f["detail"]) < 500, f"{name}: unbounded detail field"


def test_scale_10000_items_stays_bounded():
    for name, (client_name, _methods) in COLLECTOR_CALLS.items():
        sess = FakeSession({client_name: ScriptedClient(
            responses=_big_ok_responses(client_name, 10000))})
        facts = COLLECTOR_FN[name](sess, "us-east-1")
        _assert_invariants(name, facts)
    print("PASS: test_scale_10000_items_stays_bounded")


def test_every_fault_mode_on_every_call_yields_a_fact_not_a_crash():
    failures = 0
    for name, (client_name, methods) in COLLECTOR_CALLS.items():
        for method in methods:
            for mode, exc in FAULT_MODES.items():
                sess = FakeSession({client_name: ScriptedClient(
                    responses=_big_ok_responses(client_name, 5),
                    errors={method: exc})})
                try:
                    facts = COLLECTOR_FN[name](sess, "us-east-1")
                except Exception as e:  # noqa: BLE001
                    print(f"FAIL: {name} raised on {method}/{mode}: {type(e).__name__}")
                    failures += 1
                    continue
                _assert_invariants(name, facts)
    assert failures == 0, f"{failures} collector(s) raised under fault injection"
    print("PASS: test_every_fault_mode_on_every_call_yields_a_fact_not_a_crash")


def test_client_construction_failure_is_handled():
    # A session whose .client() itself raises (bad region, missing service).
    class BadSession:
        def client(self, _name):
            raise RuntimeError("could not construct client")
    for name in COLLECTOR_CALLS:
        facts = COLLECTOR_FN[name](BadSession(), "us-east-1")
        _assert_invariants(name, facts)
        assert any(f["status"] == "ERROR" or f["status"].startswith("ERROR")
                   for f in facts), f"{name}: client failure not marked ERROR"
    print("PASS: test_client_construction_failure_is_handled")


def test_empty_account_yields_clean_not_error():
    # An account with nothing configured: empty lists, not errors. Collectors
    # should report NONE/NO_COVERAGE/NO_KEYS, never ERROR.
    sess = FakeSession({
        "securityhub": ScriptedClient(errors={
            "describe_hub": FakeClientError("InvalidAccessException")}),
        "accessanalyzer": ScriptedClient(responses={"list_analyzers": {"analyzers": []}}),
        "inspector2": ScriptedClient(responses={"list_coverage": {"coveredResources": []}}),
        "guardduty": ScriptedClient(responses={"list_detectors": {"DetectorIds": []}}),
        "backup": ScriptedClient(responses={"list_backup_plans": {"BackupPlansList": []},
                                            "list_protected_resources": {"Results": []}}),
        "kms": ScriptedClient(responses={"list_keys": {"Keys": []}}),
        "config": ScriptedClient(responses={
            "describe_configuration_recorder_status": {"ConfigurationRecordersStatus": []},
            "get_discovered_resource_counts": {"resourceCounts": []},
            "describe_compliance_by_config_rule": {"ComplianceByConfigRules": []}}),
        "cloudtrail": ScriptedClient(responses={"describe_trails": {"trailList": []}}),
        "s3": ScriptedClient(responses={"list_buckets": {"Buckets": []}}),
        "iam": ScriptedClient(responses={
            "get_account_summary": {"SummaryMap": {}}},
            errors={"get_account_password_policy": FakeClientError("NoSuchEntity")}),
    })
    for name, (client_name, _m) in COLLECTOR_CALLS.items():
        facts = COLLECTOR_FN[name](sess, "us-east-1")
        _assert_invariants(name, facts)
        for f in facts:
            assert not f["status"].startswith("ERROR"), \
                f"{name}: empty account wrongly reported ERROR ({f})"
    print("PASS: test_empty_account_yields_clean_not_error")


def test_malformed_response_shapes_do_not_crash():
    # Responses missing expected keys or with wrong types.
    sess = FakeSession({
        "securityhub": ScriptedClient(responses={"describe_hub": {},
                                                 "get_findings": {}}),
        "accessanalyzer": ScriptedClient(responses={"list_analyzers": {},
                                                    "list_findings": {}}),
        "inspector2": ScriptedClient(responses={"list_coverage": {}}),
        "guardduty": ScriptedClient(responses={"list_detectors": {},
                                               "get_detector": {}}),
        "backup": ScriptedClient(responses={"list_backup_plans": {},
                                            "list_protected_resources": {}}),
        "kms": ScriptedClient(responses={"list_keys": {}}),
        "config": ScriptedClient(responses={
            "describe_configuration_recorder_status": {},
            "get_discovered_resource_counts": {},
            "describe_compliance_by_config_rule": {}}),
        "cloudtrail": ScriptedClient(responses={"describe_trails": {}}),
        "s3": ScriptedClient(responses={"list_buckets": {}}),
        "iam": ScriptedClient(responses={"get_account_summary": {},
                                         "get_account_password_policy": {}}),
    })
    for name in COLLECTOR_CALLS:
        facts = COLLECTOR_FN[name](sess, "us-east-1")
        _assert_invariants(name, facts)
    print("PASS: test_malformed_response_shapes_do_not_crash")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
