# Read-only AWS posture collectors (Layer 1, broadened).
#
# Each function queries ONE AWS service with read-only describe/list/get calls
# and returns a list of dated posture facts. Facts are telemetry, never
# statuses: nothing here decides that a control is Implemented. A fact records
# what a read-only API returned at a point in time, for a human (or a gated
# pipeline step) to interpret.
#
# Read-only by construction. The complete set of API actions this module may
# call is enumerated in READ_ONLY_ACTIONS below; the collector driver asserts
# every call it makes is in that set, and refuses admin-looking identities.
# Adding a service means adding its read-only actions to that set on purpose,
# which is a reviewable change rather than a silent permission widening.
#
# Every collector is written to be offline-testable: it takes a boto3-style
# session whose clients can be stubbed, catches client errors, and never
# raises out of a single service failure (one unreachable service must not
# sink a whole collection run).

from datetime import datetime, timezone

# The exhaustive read-only allowlist. If an action is not here, the driver
# refuses to run it. Keep this list in sync with the calls each collector makes.
READ_ONLY_ACTIONS = {
    "sts:GetCallerIdentity",
    "config:DescribeComplianceByConfigRule",
    "securityhub:GetFindings",
    "securityhub:DescribeHub",
    "accessanalyzer:ListAnalyzers",
    "accessanalyzer:ListFindings",
    "inspector2:ListCoverage",
    "inspector2:ListFindings",
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
    "backup:ListBackupPlans",
    "backup:ListProtectedResources",
    "kms:ListKeys",
    "kms:GetKeyRotationStatus",
    # Config is the aggregator that absorbs breadth: it records the config
    # state of all supported resource types across every service in scope.
    "config:DescribeConfigurationRecorderStatus",
    "config:DescribeConfigurationRecorders",
    "config:DescribeComplianceByConfigRule",
    "config:GetDiscoveredResourceCounts",
    # CloudTrail: account-wide audit capture across all services.
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    # S3: account-wide data-at-rest and public-access posture.
    "s3:ListAllMyBuckets",
    "s3:GetBucketPublicAccessBlock",
    "s3control:GetPublicAccessBlock",
    # IAM: account-wide identity posture.
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    "iam:ListUsers",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fact(service, check, status, detail, region):
    """Uniform posture-fact shape. status is a short machine token; detail is
    a human-readable, non-sensitive summary. Never include ARNs of principals,
    account IDs, or finding bodies that could carry sensitive specifics."""
    return {
        "service": service,
        "check": check,
        "status": status,
        "detail": detail,
        "region": region,
        "collected_at": _now(),
    }


def _client_error_name(exc):
    try:
        return exc.response.get("Error", {}).get("Code", type(exc).__name__)
    except AttributeError:
        return type(exc).__name__


def collect_security_hub(session, region):
    """Security Hub enablement and a count of active FAILED control findings.
    Records posture, not the findings themselves (those can carry specifics)."""
    facts = []
    try:
        sh = session.client("securityhub")
    except Exception as e:  # noqa: BLE001 - client construction can fail offline
        return [_fact("securityhub", "client", "ERROR", type(e).__name__, region)]
    try:
        sh.describe_hub()
        facts.append(_fact("securityhub", "enabled", "ENABLED",
                           "Security Hub is enabled in this region", region))
    except Exception as e:  # noqa: BLE001
        name = _client_error_name(e)
        if "InvalidAccess" in name or "ResourceNotFound" in name:
            facts.append(_fact("securityhub", "enabled", "NOT_ENABLED",
                               "Security Hub is not enabled in this region", region))
            return facts
        facts.append(_fact("securityhub", "enabled", f"ERROR:{name}",
                           "Could not determine Security Hub status", region))
        return facts
    try:
        resp = sh.get_findings(Filters={
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        }, MaxResults=100)
        count = len(resp.get("Findings", []))
        more = "+" if resp.get("NextToken") else ""
        facts.append(_fact("securityhub", "failed_findings", "OBSERVED",
                           f"{count}{more} active failed control findings "
                           "(first page)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("securityhub", "failed_findings", f"ERROR:{_client_error_name(e)}",
                           "Could not read Security Hub findings", region))
    return facts


def collect_access_analyzer(session, region):
    """IAM Access Analyzer presence and count of active external-access
    findings. Counts only; finding detail can name resources."""
    facts = []
    try:
        aa = session.client("accessanalyzer")
    except Exception as e:  # noqa: BLE001
        return [_fact("accessanalyzer", "client", "ERROR", type(e).__name__, region)]
    try:
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("accessanalyzer", "analyzer", f"ERROR:{_client_error_name(e)}",
                      "Could not list Access Analyzers", region)]
    if not analyzers:
        return [_fact("accessanalyzer", "analyzer", "NONE",
                      "No IAM Access Analyzer configured in this region", region)]
    facts.append(_fact("accessanalyzer", "analyzer", "PRESENT",
                       f"{len(analyzers)} analyzer(s) configured", region))
    arn = analyzers[0].get("arn")
    try:
        findings = aa.list_findings(
            analyzerArn=arn,
            filter={"status": {"eq": ["ACTIVE"]}}).get("findings", [])
        facts.append(_fact("accessanalyzer", "active_findings", "OBSERVED",
                           f"{len(findings)} active finding(s) on first analyzer "
                           "(first page)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("accessanalyzer", "active_findings",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list Access Analyzer findings", region))
    return facts


def collect_inspector(session, region):
    """Amazon Inspector coverage: is anything actively scanned."""
    try:
        insp = session.client("inspector2")
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "client", "ERROR", type(e).__name__, region)]
    try:
        cov = insp.list_coverage(maxResults=100).get("coveredResources", [])
        active = sum(1 for c in cov if c.get("scanStatus", {}).get("statusCode") == "ACTIVE")
        status = "ACTIVE" if active else ("COVERED_INACTIVE" if cov else "NO_COVERAGE")
        return [_fact("inspector2", "coverage", status,
                      f"{active} actively scanned of {len(cov)} covered resources "
                      "(first page)", region)]
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "coverage", f"ERROR:{_client_error_name(e)}",
                      "Could not read Inspector coverage", region)]


def collect_guardduty(session, region):
    """GuardDuty: is a detector present and enabled in this region."""
    try:
        gd = session.client("guardduty")
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "client", "ERROR", type(e).__name__, region)]
    try:
        ids = gd.list_detectors().get("DetectorIds", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "detector", f"ERROR:{_client_error_name(e)}",
                      "Could not list GuardDuty detectors", region)]
    if not ids:
        return [_fact("guardduty", "detector", "NONE",
                      "No GuardDuty detector in this region", region)]
    try:
        det = gd.get_detector(DetectorId=ids[0])
        status = det.get("Status", "UNKNOWN")
        return [_fact("guardduty", "detector",
                      "ENABLED" if status == "ENABLED" else status,
                      f"Detector status {status}", region)]
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "detector", f"ERROR:{_client_error_name(e)}",
                      "Could not read GuardDuty detector", region)]


def collect_backup(session, region):
    """AWS Backup: are backup plans defined and protecting resources."""
    try:
        bk = session.client("backup")
    except Exception as e:  # noqa: BLE001
        return [_fact("backup", "client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        plans = bk.list_backup_plans().get("BackupPlansList", [])
        facts.append(_fact("backup", "plans",
                           "PRESENT" if plans else "NONE",
                           f"{len(plans)} backup plan(s)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("backup", "plans", f"ERROR:{_client_error_name(e)}",
                           "Could not list backup plans", region))
    try:
        protected = bk.list_protected_resources().get("Results", [])
        facts.append(_fact("backup", "protected_resources", "OBSERVED",
                           f"{len(protected)} protected resource(s) (first page)",
                           region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("backup", "protected_resources",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list protected resources", region))
    return facts


def collect_kms(session, region):
    """KMS: fraction of customer keys with automatic rotation enabled.
    Reports an aggregate, not individual key identifiers."""
    try:
        kms = session.client("kms")
    except Exception as e:  # noqa: BLE001
        return [_fact("kms", "client", "ERROR", type(e).__name__, region)]
    try:
        keys = kms.list_keys(Limit=1000).get("Keys", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("kms", "keys", f"ERROR:{_client_error_name(e)}",
                      "Could not list KMS keys", region)]
    if not keys:
        return [_fact("kms", "key_rotation", "NO_KEYS",
                      "No KMS keys in this region", region)]
    rotating = 0
    checked = 0
    for k in keys:
        try:
            r = kms.get_key_rotation_status(KeyId=k["KeyId"])
            checked += 1
            if r.get("KeyRotationEnabled"):
                rotating += 1
        except Exception:  # noqa: BLE001 - AWS-managed keys reject this call; skip
            continue
    return [_fact("kms", "key_rotation", "OBSERVED",
                  f"{rotating} of {checked} customer keys have automatic "
                  "rotation enabled", region)]


def collect_config(session, region):
    """AWS Config: the breadth aggregator. Reports whether the configuration
    recorder is on, how many resources it has discovered (the 400-service
    breadth collapsed into one count), and the compliance tally across rules.
    A count and aggregate posture, never per-resource detail."""
    try:
        cfg = session.client("config")
    except Exception as e:  # noqa: BLE001
        return [_fact("config", "client", "ERROR", type(e).__name__, region)]
    facts = []
    # 1. Is the recorder running? Without it, breadth coverage is zero.
    try:
        statuses = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", [])
        recording = sum(1 for s in statuses if s.get("recording"))
        if not statuses:
            facts.append(_fact("config", "recorder", "NONE",
                               "No Config recorder in this region", region))
        else:
            facts.append(_fact("config", "recorder",
                               "RECORDING" if recording else "STOPPED",
                               f"{recording} of {len(statuses)} recorder(s) recording",
                               region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "recorder", f"ERROR:{_client_error_name(e)}",
                           "Could not read Config recorder status", region))
    # 2. How many resources has Config discovered? This is the 400-service
    #    breadth expressed as one number: every recorded resource, all services.
    try:
        counts = cfg.get_discovered_resource_counts().get("resourceCounts", [])
        total = sum(c.get("count", 0) for c in counts)
        facts.append(_fact("config", "discovered_resources", "OBSERVED",
                           f"{total} resources across {len(counts)} resource "
                           "type(s) recorded", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "discovered_resources",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read discovered resource counts", region))
    # 3. Rule compliance tally (aggregate, not per-rule bodies).
    try:
        rules = cfg.describe_compliance_by_config_rule().get(
            "ComplianceByConfigRules", [])
        compliant = sum(1 for r in rules
                        if r.get("Compliance", {}).get("ComplianceType") == "COMPLIANT")
        noncompliant = sum(1 for r in rules
                           if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT")
        facts.append(_fact("config", "rule_compliance", "OBSERVED",
                           f"{compliant} compliant, {noncompliant} non-compliant "
                           f"of {len(rules)} rule(s) (first page)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "rule_compliance",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read Config rule compliance", region))
    return facts


def collect_cloudtrail(session, region):
    """AWS CloudTrail: account-wide audit capture. Reports whether a
    multi-region trail exists and is logging. One trail covers all services."""
    try:
        ct = session.client("cloudtrail")
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "client", "ERROR", type(e).__name__, region)]
    try:
        trails = ct.describe_trails().get("trailList", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "trails", f"ERROR:{_client_error_name(e)}",
                      "Could not describe CloudTrail trails", region)]
    if not trails:
        return [_fact("cloudtrail", "trails", "NONE",
                      "No CloudTrail trails visible in this region", region)]
    multiregion = sum(1 for t in trails if t.get("IsMultiRegionTrail"))
    logging_on = 0
    for t in trails:
        try:
            st = ct.get_trail_status(Name=t.get("TrailARN") or t.get("Name"))
            if st.get("IsLogging"):
                logging_on += 1
        except Exception:  # noqa: BLE001 - status of one trail must not sink the rest
            continue
    return [_fact("cloudtrail", "trails", "OBSERVED",
                  f"{len(trails)} trail(s), {multiregion} multi-region, "
                  f"{logging_on} actively logging", region)]


def collect_s3(session, region):
    """Amazon S3: account-wide data-at-rest surface. Reports bucket count and
    how many have account-level or bucket-level public access blocked. An
    aggregate posture across all buckets, not per-bucket detail."""
    try:
        s3 = session.client("s3")
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "client", "ERROR", type(e).__name__, region)]
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "buckets", f"ERROR:{_client_error_name(e)}",
                      "Could not list S3 buckets", region)]
    if not buckets:
        return [_fact("s3", "buckets", "NONE", "No S3 buckets in this account", region)]
    blocked = 0
    checked = 0
    for b in buckets:
        try:
            pab = s3.get_public_access_block(Bucket=b["Name"]).get(
                "PublicAccessBlockConfiguration", {})
            checked += 1
            if all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                        "BlockPublicPolicy", "RestrictPublicBuckets")):
                blocked += 1
        except Exception:  # noqa: BLE001 - one bucket's ACL read must not sink the run
            checked += 1
            continue
    return [_fact("s3", "public_access_block", "OBSERVED",
                  f"{blocked} of {checked} buckets fully block public access "
                  f"({len(buckets)} total)", region)]


def collect_iam(session, region):
    """IAM: account-wide identity posture. Reports MFA/password-policy and the
    account summary tallies. IAM is global; region is recorded for provenance."""
    try:
        iam = session.client("iam")
    except Exception as e:  # noqa: BLE001
        return [_fact("iam", "client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        users = summary.get("Users", 0)
        mfa_devices = summary.get("MFADevices", 0)
        facts.append(_fact("iam", "account_summary", "OBSERVED",
                           f"{users} users, {mfa_devices} MFA device(s), "
                           f"{summary.get('Roles', 0)} roles", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("iam", "account_summary",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read IAM account summary", region))
    try:
        iam.get_account_password_policy()
        facts.append(_fact("iam", "password_policy", "PRESENT",
                           "Account password policy is set", region))
    except Exception as e:  # noqa: BLE001
        name = _client_error_name(e)
        if "NoSuchEntity" in name:
            facts.append(_fact("iam", "password_policy", "NONE",
                               "No account password policy set", region))
        else:
            facts.append(_fact("iam", "password_policy", f"ERROR:{name}",
                               "Could not read account password policy", region))
    return facts


# Ordered so a driver can iterate. Each entry: (name, function).
COLLECTORS = [
    ("security_hub", collect_security_hub),
    ("access_analyzer", collect_access_analyzer),
    ("inspector", collect_inspector),
    ("guardduty", collect_guardduty),
    ("backup", collect_backup),
    ("kms", collect_kms),
    ("config", collect_config),
    ("cloudtrail", collect_cloudtrail),
    ("s3", collect_s3),
    ("iam", collect_iam),
]
