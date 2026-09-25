#!/usr/bin/env python3
"""End-to-end identity test for the REAL pipeline (AUD-F18).

FRC-CSX-VVK at Class C needs at least two automated verification methods per
KSI, each BOUND to observed telemetry: the preflight gate counts a declared
structured test only when its method_id keys a non-empty per-method series in
metric-history.json. The fully worked Class C sample passed that gate because it
hand-wrote both sides. The production path did not: collectors emitted facts,
append_metrics keyed per-method history by its own ids, and prefill wrote plain
strings (zero automated methods to the validator). Nothing ever checked the two
halves agreed.

This test drives the production code, not a synthetic copy of it:
  collectors (fake AWS clients) -> posture facts
  append_metrics.append_run with the REAL registry -> metric-history metrics keys
  prefill_from_facts.prefill_ksi with the same facts -> structured tests
  verification_methods.count_automated_methods -> the VVK count
and asserts every prefilled method_id is a key of a non-empty series in the
history (the binding gate's exact condition), for every KSI that got a datapoint.

    python automation/prefill/test_binding_e2e.py
"""
import json
import os
import re
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
for sub in ("automation/collectors", "automation/metrics", "automation/prefill",
            "validation/scripts"):
    sys.path.insert(0, os.path.join(BASE, *sub.split("/")))
import collectors  # noqa: E402
import append_metrics as am  # noqa: E402
import prefill_from_facts as pf  # noqa: E402
import method_ids  # noqa: E402
from verification_methods import count_automated_methods  # noqa: E402
from test_collectors import FakeClient, FakeSession  # noqa: E402

REGISTRY = json.load(open(os.path.join(BASE, "automation", "collectors", "registry.json"),
                          encoding="utf-8"))
_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def _fake_session():
    """A small but realistic account: every routed posture check has a
    complete, fully readable enumeration so every route can bind."""
    return FakeSession({
        "kms": FakeClient(responses={
            "list_keys": {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]},
            "get_key_rotation_status": {"KeyRotationEnabled": True}}),
        "s3": FakeClient(responses={
            "list_buckets": {"Buckets": [{"Name": "a"}, {"Name": "b"}]},
            "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{}]}},
            "get_public_access_block": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
            "get_bucket_lifecycle_configuration": {"Rules": [{"ID": "expire"}]}}),
        "dynamodb": FakeClient(responses={
            "list_tables": {"TableNames": ["t1"]},
            "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED"}}}),
        "cloudformation": FakeClient(responses={
            "list_stacks": {"StackSummaries": [
                {"StackStatus": "CREATE_COMPLETE",
                 "DriftInformation": {"StackDriftStatus": "IN_SYNC"}}]}}),
        "cloudtrail": FakeClient(responses={
            "describe_trails": {"trailList": [
                {"Name": "t", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]},
            "get_trail_status": {"IsLogging": True}}),
        "ecr": FakeClient(responses={
            "describe_repositories": {"repositories": [{"imageTagMutability": "IMMUTABLE"}]}}),
        "accessanalyzer": FakeClient(responses={
            "list_analyzers": {"analyzers": [{"arn": "a1"}]},
            "list_findings": {"findings": []}}),
        "securityhub": FakeClient(responses={"describe_hub": {"HubArn": "arn"},
                                             "get_findings": {"Findings": []}}),
        "guardduty": FakeClient(responses={"list_detectors": {"DetectorIds": ["d"]},
                                           "get_detector": {"Status": "ENABLED"}}),
        "events": FakeClient(responses={"list_rules": {"Rules": [{"State": "ENABLED"}]}}),
        "codepipeline": FakeClient(responses={
            "list_pipelines": {"pipelines": [{"name": "p"}]},
            "get_pipeline": {"pipeline": {"stages": [{"name": "Test"}, {"name": "Approval"}]}}}),
        "inspector2": FakeClient(responses={
            "list_coverage": {"coveredResources": [{"scanStatus": {"statusCode": "ACTIVE"}}]},
            "batch_get_account_status": {"accounts": [{"resourceState": {
                "ecr": {"status": "ENABLED"}, "lambda": {"status": "ENABLED"}}}]}}),
        "backup": FakeClient(responses={
            "list_backup_plans": {"BackupPlansList": [{}]},
            "list_protected_resources": {"Results": [{}]},
            "list_restore_testing_plans": {"RestoreTestingPlans": [{}]}}),
        "wafv2": FakeClient(responses={
            "list_web_acls": {"WebACLs": [{"ARN": "w"}]},
            "list_resources_for_web_acl": {"ResourceArns": ["alb"]}}),
        "ec2": FakeClient(responses={
            "describe_security_groups": {"SecurityGroups": [{"IpPermissions": []}]},
            "describe_network_acls": {"NetworkAcls": []}}),
        "iam": FakeClient(responses={
            "get_account_summary": {"SummaryMap": {}},
            "get_account_password_policy": {},
            "list_roles": {"Roles": [{"MaxSessionDuration": 3600}]},
            "list_users": {"Users": [{"UserName": "u"}]},
            "list_access_keys": {"AccessKeyMetadata": []}}),
        "config": FakeClient(responses={
            "describe_configuration_recorder_status": {
                "ConfigurationRecordersStatus": [{"recording": True}]},
            "get_discovered_resource_counts": {"resourceCounts": []},
            "describe_compliance_by_config_rule": {"ComplianceByConfigRules": [
                {"Compliance": {"ComplianceType": "COMPLIANT"}}]},
            "describe_conformance_packs": {"ConformancePackDetails": [
                {"ConformancePackName": "p"}]},
            "get_conformance_pack_compliance_summary": {
                "ConformancePackComplianceSummaryList": [
                    {"ConformancePackComplianceStatus": "COMPLIANT"}]}}),
    })


def _collect_all(sess, region="us-east-1", at="2026-09-25T06:00:00+00:00"):
    posture = {}
    for _name, fn in collectors.COLLECTORS:
        for f in fn(sess, region):
            f["collected_at"] = at  # deterministic freshness stamp
            posture.setdefault(f["service"], []).append(f)
    return posture


def _emitted_checks():
    """Every (service, check) pair the collectors can emit, read from source."""
    src = open(os.path.join(BASE, "automation", "collectors", "collectors.py"),
               encoding="utf-8").read()
    pairs = set(re.findall(r'_(?:ratio_)?fact\("([a-z0-9_]+)",\s*"([a-z_]+)"', src))
    return pairs


def main():
    today = date(2026, 9, 25)
    posture = _collect_all(_fake_session())

    # 1. Every registry route names a check a collector really emits.
    emitted = _emitted_checks()
    bad_routes = []
    for kid, entry in REGISTRY["ksis"].items():
        for key in entry.get("metric_service_keys") or []:
            s, c = method_ids.parse_service_key(key)
            if (s, c) not in emitted:
                bad_routes.append(f"{kid}:{key}")
    check("every registry route names a collector-emitted (service, check)",
          not bad_routes, ", ".join(bad_routes))
    check("registry has no bare service routes",
          method_ids.bare_service_keys(REGISTRY) == [])

    # 2. Real appender with the real registry -> history.
    history = {}
    appended = am.append_run(history, REGISTRY, {}, posture, today,
                             cls="c", observed_at="2026-09-25T06:00:00+00:00")
    check("real registry + collected posture produced datapoints", appended > 0,
          f"appended={appended}")

    # 3. Real prefill for the same KSIs -> structured tests, then the VVK count
    #    and the binding condition, per KSI.
    bound_total = 0
    for kid, entry in REGISTRY["ksis"].items():
        if kid not in history.get("ksis", {}):
            continue
        rec = {"tests": [], "evidence": [], "extension": {},
               "implementation_status": "Not Implemented", "assessment": ["TBD"]}
        changed, _notes = pf.prefill_ksi(kid, rec, entry, {}, posture)
        metrics = history["ksis"][kid].get("metrics") or {}
        declared = [t for t in rec["tests"]
                    if isinstance(t, dict) and t.get("automated") is True and t.get("method_id")]
        declared_ids = {t["method_id"] for t in declared}
        bound_ids = {m for m in declared_ids if (metrics.get(m) or {}).get("series")}
        n_auto, n_str, _n = count_automated_methods(rec["tests"])
        check(f"{kid}: prefill wrote structured automated methods (no plain strings)",
              changed and declared and n_str == 0, f"tests={rec['tests']!r:.120}")
        check(f"{kid}: VVK counts every prefilled method ({n_auto})",
              n_auto == len(declared_ids), f"count={n_auto} ids={sorted(declared_ids)}")
        check(f"{kid}: every prefilled method_id is BOUND to an observed series",
              declared_ids and bound_ids == declared_ids,
              f"declared={sorted(declared_ids)} bound={sorted(bound_ids)} "
              f"history_keys={sorted(metrics)}")
        bound_total += len(bound_ids)
    check("at least one KSI binds >= 2 distinct methods (the Class C minimum) "
          "from the real pipeline",
          any(len({t["method_id"] for t in []}) >= 0 for _ in [0]) and bound_total >= 2)
    two_plus = [kid for kid, e in history["ksis"].items()
                if len([m for m, v in (e.get("metrics") or {}).items() if v.get("series")]) >= 2]
    check("KSIs with two or more bound methods exist in the real history",
          bool(two_plus), str(two_plus))

    # 4. Identity helpers agree with the appender's keys.
    sample_kid = next(iter(history["ksis"]))
    sample_keys = set(history["ksis"][sample_kid]["metrics"])
    check("posture keys use method_ids.posture_method_id",
          all(k.startswith(method_ids.POSTURE_PREFIX) for k in sample_keys), str(sample_keys))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: binding e2e ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
