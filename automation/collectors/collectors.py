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


# Ordered so a driver can iterate. Each entry: (name, function).
COLLECTORS = [
    ("security_hub", collect_security_hub),
    ("access_analyzer", collect_access_analyzer),
    ("inspector", collect_inspector),
    ("guardduty", collect_guardduty),
    ("backup", collect_backup),
    ("kms", collect_kms),
]
