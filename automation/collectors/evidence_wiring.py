#!/usr/bin/env python3
"""Turn read-only collector facts into SDR evidence entries.

This wires the collector telemetry into the official SDR schema's
`keySecurityIndicators[].ksiEvidence[]` array. Each entry it produces is a
valid `evidence` object per the FedRAMP SDR schema:
    evidenceType         (enum: Log/Report/Screenshot/Configuration/Policy/
                          Procedure/Audit Record)
    evidenceDescription  human-readable, non-sensitive summary
    evidenceLocation     URI to the underlying artifact (Config export,
                          CloudTrail record, etc.)
    evidenceText         short inline telemetry summary
    lastUpdated          date the fact was observed

TRUST BOUNDARY (unchanged): this helper NEVER sets or changes an
implementation/validation/assessment status. A fact is telemetry, not a
determination. `evidenceLocation` is populated as a source POINTER; when the
collector cannot know the durable artifact URI, it emits a clearly-marked
placeholder (a `sdr://` pseudo-URI naming the source) that a human replaces
with the real evidence-store location. It never fabricates an https URL that
implies an artifact exists where none does.

Offline by construction: pure functions over the fact dicts the collectors
emit (service/check/status/detail/region/observed_at). No AWS, no network.
"""

# collector service -> (SDR evidenceType, source-kind used to build the pointer)
_SERVICE_EVIDENCE = {
    "config": ("Configuration", "aws-config"),
    "cloudtrail": ("Audit Record", "aws-cloudtrail"),
    "securityhub": ("Report", "aws-securityhub"),
    "accessanalyzer": ("Report", "aws-accessanalyzer"),
    "inspector2": ("Report", "aws-inspector"),
    "guardduty": ("Log", "aws-guardduty"),
    "backup": ("Configuration", "aws-backup"),
    "kms": ("Configuration", "aws-kms"),
    "cloudformation": ("Configuration", "aws-cloudformation"),
    "wafv2": ("Configuration", "aws-wafv2"),
    "ec2": ("Configuration", "aws-ec2"),
    "ecr": ("Configuration", "aws-ecr"),
    "s3": ("Configuration", "aws-s3"),
    "s3control": ("Configuration", "aws-s3control"),
    "dynamodb": ("Configuration", "aws-dynamodb"),
    "iam": ("Policy", "aws-iam"),
    "events": ("Configuration", "aws-eventbridge"),
    "codepipeline": ("Configuration", "aws-codepipeline"),
}

_DEFAULT_TYPE = "Report"

# Statuses that indicate the read itself failed; these do not become evidence
# (a failed read is not evidence of anything about the control).
_ERROR_PREFIX = "ERROR"


def _pointer(service, check, region, location_base=None):
    """Build the evidenceLocation.

    If the caller supplies a real evidence-store base URI, the pointer is a
    concrete https URL under it. Otherwise it is an explicit `sdr://` pseudo-URI
    that names the AWS source and is obviously a placeholder for a human to
    replace, never a fake https link.
    """
    slug = f"{service}/{check}/{region}"
    if location_base:
        base = location_base.rstrip("/")
        return f"{base}/{slug}.json"
    return f"sdr://placeholder/{slug}  (replace with the real evidence-store URI)"


def fact_to_evidence(fact, location_base=None):
    """Convert one collector fact into an SDR evidence dict, or None if the
    fact records a read error (which is not evidence)."""
    if not isinstance(fact, dict):
        return None
    status = str(fact.get("status", ""))
    if status.startswith(_ERROR_PREFIX):
        return None
    service = fact.get("service", "unknown")
    check = fact.get("check", "unknown")
    region = fact.get("region", "unknown")
    ev_type, _kind = _SERVICE_EVIDENCE.get(service, (_DEFAULT_TYPE, service))
    detail = fact.get("detail", "")
    observed = fact.get("observed_at") or fact.get("timestamp")

    evidence = {
        "evidenceType": ev_type,
        "evidenceDescription": f"{service}:{check} = {status}. {detail}".strip(),
        "evidenceLocation": _pointer(service, check, region, location_base),
        "evidenceText": f"{service}:{check} status={status} region={region}",
    }
    if observed:
        # SDR schema wants a date (not datetime) for evidence lastUpdated.
        evidence["lastUpdated"] = str(observed)[:10]
    return evidence


def facts_to_evidence(facts, location_base=None):
    """Map a list of collector facts to a list of SDR evidence entries,
    dropping read-error facts."""
    out = []
    for f in facts or []:
        ev = fact_to_evidence(f, location_base)
        if ev is not None:
            out.append(ev)
    return out


def attach_evidence(ksi_record, facts, location_base=None, replace=False):
    """Populate a records-store KSI entry's `evidence` list from facts.

    ksi_record is one value from records["ksi"][ksi_id]. This ONLY touches the
    `evidence` array; implementation_status and every statement field are left
    exactly as they were. Returns the number of evidence entries added.

    replace=False appends (de-duplicated by evidenceLocation); replace=True
    swaps the evidence list for the freshly derived one.
    """
    if not isinstance(ksi_record, dict):
        raise TypeError("ksi_record must be a dict")
    new = facts_to_evidence(facts, location_base)
    if replace:
        ksi_record["evidence"] = new
        return len(new)
    existing = ksi_record.get("evidence", []) or []
    seen = {e.get("evidenceLocation") for e in existing if isinstance(e, dict)}
    added = 0
    for ev in new:
        if ev["evidenceLocation"] in seen:
            continue
        existing.append(ev)
        seen.add(ev["evidenceLocation"])
        added += 1
    ksi_record["evidence"] = existing
    return added
