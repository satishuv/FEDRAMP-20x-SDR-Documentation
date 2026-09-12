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
    # Optional third-party evidence sources (opt-in; see thirdparty_adapters.py).
    "crowdstrike": ("Log", "crowdstrike-falcon"),
    "wiz": ("Report", "wiz"),
}

_DEFAULT_TYPE = "Report"

# Statuses that indicate the read itself failed; these do not become evidence
# (a failed read is not evidence of anything about the control).
_ERROR_PREFIX = "ERROR"


def evidence_hash(artifact):
    """SHA-256 of an evidence artifact, for tamper-evident traceability.

    Accepts bytes, str, or a JSON-serializable object (dict/list). Objects are
    hashed over their canonical (sorted-key, compact) JSON encoding so the same
    logical content always yields the same digest regardless of key order or
    whitespace. Returns a lowercase hex digest string prefixed 'sha256:'.

    This is a traceability aid, not a security control: it lets a reviewer
    confirm the evidence object in the SDR is the same bytes that were
    collected, and lets CI detect a silently-edited evidence artifact. It never
    sets a status or makes a determination.
    """
    import hashlib
    import json as _json

    if isinstance(artifact, bytes):
        data = artifact
    elif isinstance(artifact, str):
        data = artifact.encode("utf-8")
    else:
        data = _json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
        # Tamper-evident digest of the source fact. A reviewer or CI can
        # recompute it to confirm the evidence entry reflects the fact that was
        # collected and has not been silently edited. Carried in the extension
        # namespace so the official evidence object stays schema-clean.
        "xEvidenceContentHash": evidence_hash(fact),
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


# --- Evidence adapters -----------------------------------------------------
#
# An adapter reads raw data from ONE source (a scan CSV, a config export, a
# vulnerability report) and yields collector-shaped fact dicts. Those facts
# flow through fact_to_evidence, so every adapter's output lands in the SDR as
# a schema-valid evidence object with a content hash, using the same trust
# boundary as the AWS collectors: telemetry only, never a status determination.
#
# To add a source, subclass EvidenceAdapter, implement collect(), and register
# it. This is the extension point the reviews asked for; the AWS collectors are
# one producer of facts, adapters are another.

_ADAPTERS = {}


class EvidenceAdapter:
    """Base class for an evidence source. Subclasses set `name` and implement
    `collect(raw)`, returning an iterable of collector-shaped fact dicts:
        {service, check, status, detail, region, observed_at}
    The fact is hashed and mapped to an SDR evidence object downstream."""

    name = "abstract"
    service = "adapter"

    def collect(self, raw):  # pragma: no cover - abstract
        raise NotImplementedError

    def to_evidence(self, raw, location_base=None):
        """Run collect() and map every fact to an SDR evidence object."""
        return facts_to_evidence(list(self.collect(raw)), location_base)


def register_adapter(adapter):
    """Register an EvidenceAdapter instance (or subclass) under its name."""
    inst = adapter() if isinstance(adapter, type) else adapter
    if not isinstance(inst, EvidenceAdapter):
        raise TypeError("adapter must be an EvidenceAdapter")
    _ADAPTERS[inst.name] = inst
    return inst


def get_adapter(name):
    return _ADAPTERS.get(name)


def list_adapters():
    return sorted(_ADAPTERS)


class CsvCountAdapter(EvidenceAdapter):
    """Reference adapter: turns a metric name and an observed/total count into a
    single evidence fact (e.g. a vulnerability-scan patch-coverage row). Pure,
    offline, illustrative. `raw` is a dict:
        {check, observed, total, region?, observed_at?, detail?}"""

    name = "csv-count"
    service = "scan"

    def collect(self, raw):
        observed = raw.get("observed", 0)
        total = raw.get("total", 0)
        pct = round(100.0 * observed / total, 2) if total else 0.0
        yield {
            "service": self.service,
            "check": raw.get("check", "count"),
            "status": f"{pct}%",
            "detail": raw.get("detail", f"{observed} of {total}"),
            "region": raw.get("region", "global"),
            "observed_at": raw.get("observed_at"),
        }


register_adapter(CsvCountAdapter)
