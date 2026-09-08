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
    # BatchGet is a read (e.g. inspector2:BatchGetAccountStatus reads status).
    read_prefixes = ("Get", "List", "Describe", "BatchGet")
    for action in collectors.READ_ONLY_ACTIONS:
        verb = action.split(":", 1)[1]
        assert verb.startswith(read_prefixes), f"non-read action in allowlist: {action}"


# --- Stage 2 Bucket A collector tests (CNA, SVC, MLA) ------------------------


def test_cfn_drift_observed():
    sess = FakeSession({"cloudformation": FakeClient(responses={
        "list_stacks": {"StackSummaries": [
            {"StackStatus": "CREATE_COMPLETE", "DriftInformation": {"StackDriftStatus": "DRIFTED"}},
            {"StackStatus": "CREATE_COMPLETE", "DriftInformation": {"StackDriftStatus": "IN_SYNC"}},
            {"StackStatus": "DELETE_COMPLETE"},
        ]}})})
    fact = collectors.collect_cfn_drift(sess, "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "1 drifted, 1 in sync of 2" in fact["detail"]


def test_cfn_drift_no_stacks():
    sess = FakeSession({"cloudformation": FakeClient(responses={
        "list_stacks": {"StackSummaries": []}})})
    assert collectors.collect_cfn_drift(sess, "us-east-1")[0]["status"] == "NO_STACKS"


def test_config_conformance_present_and_compliant():
    cfg = FakeClient(responses={
        "describe_conformance_packs": {"ConformancePackDetails": [
            {"ConformancePackName": "p1"}]},
        "get_conformance_pack_compliance_summary": {
            "ConformancePackComplianceSummaryList": [
                {"ConformancePackComplianceStatus": "COMPLIANT"}]},
    })
    by = facts_by_check(collectors.collect_config_conformance(
        FakeSession({"config": cfg}), "us-east-1"))
    assert by["conformance_packs"]["status"] == "PRESENT"
    assert "1 of 1" in by["conformance_compliance"]["detail"]


def test_config_conformance_none():
    sess = FakeSession({"config": FakeClient(responses={
        "describe_conformance_packs": {"ConformancePackDetails": []}})})
    assert collectors.collect_config_conformance(
        sess, "us-east-1")[0]["status"] == "NONE"


def test_waf_associated_count():
    waf = FakeClient(responses={
        "list_web_acls": {"WebACLs": [{"ARN": "a1"}, {"ARN": "a2"}]},
        "list_resources_for_web_acl": {"ResourceArns": ["r1"]},
    })
    fact = collectors.collect_waf(FakeSession({"wafv2": waf}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2" in fact["detail"]


def test_network_segmentation_open_ingress():
    ec2 = FakeClient(responses={
        "describe_security_groups": {"SecurityGroups": [
            {"IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]},
        ]},
        "describe_network_acls": {"NetworkAcls": [{}, {}]},
    })
    by = facts_by_check(collectors.collect_network_segmentation(
        FakeSession({"ec2": ec2}), "us-east-1"))
    assert "2 security group(s), 1 with an open" in by["security_groups"]["detail"]
    assert "2 network ACL(s)" in by["network_acls"]["detail"]


def test_cloudtrail_integrity_validation():
    ct = FakeClient(responses={"describe_trails": {"trailList": [
        {"LogFileValidationEnabled": True},
        {"LogFileValidationEnabled": False},
    ]}})
    fact = collectors.collect_cloudtrail_integrity(
        FakeSession({"cloudtrail": ct}), "us-east-1")[0]
    assert "1 of 2" in fact["detail"]


def test_ecr_integrity_immutable():
    ecr = FakeClient(responses={"describe_repositories": {"repositories": [
        {"imageTagMutability": "IMMUTABLE"},
        {"imageTagMutability": "MUTABLE"},
    ]}})
    fact = collectors.collect_ecr_integrity(
        FakeSession({"ecr": ecr}), "us-east-1")[0]
    assert "1 of 2" in fact["detail"]


def test_ecr_integrity_no_repos():
    sess = FakeSession({"ecr": FakeClient(responses={
        "describe_repositories": {"repositories": []}})})
    assert collectors.collect_ecr_integrity(
        sess, "us-east-1")[0]["status"] == "NO_REPOS"


def test_s3_data_protection_encryption():
    s3 = FakeClient(responses={
        "list_buckets": {"Buckets": [{"Name": "b1"}, {"Name": "b2"}]},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {}}]}},
    })
    fact = collectors.collect_s3_data_protection(
        FakeSession({"s3": s3}), "us-east-1")[0]
    assert "2 of 2" in fact["detail"]


def test_data_retention_lifecycle_and_ttl():
    s3 = FakeClient(responses={
        "list_buckets": {"Buckets": [{"Name": "b1"}]},
        "get_bucket_lifecycle_configuration": {"Rules": [{"ID": "expire"}]},
    })
    ddb = FakeClient(responses={
        "list_tables": {"TableNames": ["t1", "t2"]},
        "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED"}},
    })
    by = facts_by_check(collectors.collect_data_retention(
        FakeSession({"s3": s3, "dynamodb": ddb}), "us-east-1"))
    assert "1 of 1" in by["lifecycle"]["detail"]
    assert "2 of 2" in by["ttl"]["detail"]


def test_siem_posture_enabled():
    ct = FakeClient(responses={"describe_trails": {"trailList": [
        {"IsMultiRegionTrail": True}]}})
    sh = FakeClient(responses={"describe_hub": {"HubArn": "arn"}})
    by = facts_by_check(collectors.collect_siem_posture(
        FakeSession({"cloudtrail": ct, "securityhub": sh}), "us-east-1"))
    assert by["siem_aggregation"]["status"] == "ENABLED"
    assert "1 trail(s), 1 multi-region" in by["siem_capture"]["detail"]


def test_siem_posture_securityhub_off():
    ct = FakeClient(responses={"describe_trails": {"trailList": []}})
    sh = FakeClient(errors={"describe_hub": FakeClientError("InvalidAccessException")})
    by = facts_by_check(collectors.collect_siem_posture(
        FakeSession({"cloudtrail": ct, "securityhub": sh}), "us-east-1"))
    assert by["siem_aggregation"]["status"] == "NOT_ENABLED"


# --- Stage 3 Bucket A collector tests (IAM, CMT, PIY, SCR, RPL) --------------


def test_iam_jit_sessions_and_keys():
    iam = FakeClient(responses={
        "list_roles": {"Roles": [
            {"MaxSessionDuration": 7200}, {"MaxSessionDuration": 3600}]},
        "list_users": {"Users": [{"UserName": "u1"}, {"UserName": "u2"}]},
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIA"}]},
    })
    by = facts_by_check(collectors.collect_iam_jit(
        FakeSession({"iam": iam}), "us-east-1"))
    assert "1 of 2 role(s) allow a session longer" in by["role_session_duration"]["detail"]
    assert "2 of 2 user(s) have a long-lived" in by["long_lived_keys"]["detail"]


def test_iam_response_wiring():
    gd = FakeClient(responses={"list_detectors": {"DetectorIds": ["d1"]}})
    ev = FakeClient(responses={"list_rules": {"Rules": [
        {"State": "ENABLED"}, {"State": "DISABLED"}]}})
    by = facts_by_check(collectors.collect_iam_response_wiring(
        FakeSession({"guardduty": gd, "events": ev}), "us-east-1"))
    assert by["response_detector"]["status"] == "ENABLED"
    assert "1 of 2 EventBridge rule(s) enabled" in by["response_rules"]["detail"]


def test_pipeline_gates_present():
    cp = FakeClient(responses={
        "list_pipelines": {"pipelines": [{"name": "p1"}, {"name": "p2"}]},
        "get_pipeline": {"pipeline": {"stages": [
            {"name": "Source"}, {"name": "SecurityScan"}]}},
    })
    fact = collectors.collect_pipeline_gates(
        FakeSession({"codepipeline": cp}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2 pipeline(s) include" in fact["detail"]


def test_pipeline_gates_none():
    sess = FakeSession({"codepipeline": FakeClient(responses={
        "list_pipelines": {"pipelines": []}})})
    assert collectors.collect_pipeline_gates(
        sess, "us-east-1")[0]["status"] == "NONE"


def test_supply_chain_scanning_enabled():
    insp = FakeClient(responses={"batch_get_account_status": {"accounts": [
        {"resourceState": {"ecr": {"status": "ENABLED"},
                           "lambda": {"status": "DISABLED"}}}]}})
    fact = collectors.collect_supply_chain_scanning(
        FakeSession({"inspector2": insp}), "us-east-1")[0]
    assert fact["status"] == "ENABLED"
    assert "ECR" in fact["detail"] and "Lambda" not in fact["detail"]


def test_supply_chain_scanning_off():
    insp = FakeClient(responses={"batch_get_account_status": {"accounts": [
        {"resourceState": {"ecr": {"status": "DISABLED"},
                           "lambda": {"status": "DISABLED"}}}]}})
    assert collectors.collect_supply_chain_scanning(
        FakeSession({"inspector2": insp}), "us-east-1")[0]["status"] == "NOT_ENABLED"


def test_restore_testing_present():
    bk = FakeClient(responses={"list_restore_testing_plans": {
        "RestoreTestingPlans": [{"RestoreTestingPlanName": "rt1"}]}})
    fact = collectors.collect_restore_testing(
        FakeSession({"backup": bk}), "us-east-1")[0]
    assert fact["status"] == "PRESENT"


def test_restore_testing_none():
    bk = FakeClient(responses={"list_restore_testing_plans": {
        "RestoreTestingPlans": []}})
    assert collectors.collect_restore_testing(
        FakeSession({"backup": bk}), "us-east-1")[0]["status"] == "NONE"


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
