#!/usr/bin/env python3
"""Export a generated Security Decision Record to OSCAL.

This is a post-generation FORMAT ADAPTER. It reads a finished SDR JSON
(sdr/json/sdr-class-<x>.json, the official FedRAMP SDR schema) and emits an
OSCAL-shaped JSON alongside it. It is a pure read -> transform -> write step:
it never touches the build pipeline, never queries AWS, and never changes any
status, implementation, validation, or assessment content.

Why OSCAL: OSCAL (Open Security Controls Assessment Language, NIST) is the
machine-readable interchange format that agency governance/risk/compliance
tools ingest. Emitting the SDR's verified facts in OSCAL lets those tools
consume the same record without a bespoke parser. This adapter makes the
provider's SDR *also available* as OSCAL; it makes no claim about whether any
particular FedRAMP process requires OSCAL. The SDR remains the source of truth
and this file is a derived view of it.

Model choice: the SDR is fundamentally a set of verified findings and evidence
about requirements (FRRs) and Key Security Indicators (KSIs), so it maps most
naturally onto the OSCAL Assessment Results model:
  - each FRR / KSI becomes an OSCAL `finding` (with its status passed through
    verbatim as a property, never re-decided here),
  - each piece of KSI evidence becomes an `observation` plus a `back-matter`
    resource carrying its evidenceLocation as an rlink,
  - NIST 800-53 control IDs present on the SDR are carried as `related-controls`
    props so control-keyed tools can join on them.

Nothing in the OSCAL output asserts a control is satisfied unless the SDR
already said so. "Not Implemented" stays "not-satisfied"; "TBD" evidence is
simply not emitted as a resource.

Offline by construction: takes a dict (or a path) in, returns a dict out. No
network, no boto3, no clock-dependence beyond an optional caller-supplied
timestamp so tests are deterministic.

Usage:
    python automation/exporters/oscal_export.py           # export every sdr/json/sdr-class-*.json
    python automation/exporters/oscal_export.py sdr/json/sdr-class-a.json
"""

import glob
import json
import os
import sys
import uuid

# Deterministic UUID namespace so the same SDR always produces the same OSCAL
# identifiers (idempotent output, clean diffs, no run-to-run churn).
_NS = uuid.UUID("6f1a0b3e-0c2d-4e5f-8a9b-0c1d2e3f4a5b")

# Map the SDR's implementation-status vocabulary to OSCAL finding target
# status. This is a pass-through relabel, not a judgement: the SDR's status is
# authoritative and is also preserved verbatim in a property.
_STATUS_TO_OSCAL = {
    "Implemented": "satisfied",
    "Partially Implemented": "not-satisfied",
    "Not Implemented": "not-satisfied",
}

# SDR evidenceType (schema enum) -> OSCAL back-matter resource "type" prop.
_EVIDENCE_TYPE = {
    "Log": "log",
    "Report": "report",
    "Screenshot": "screenshot",
    "Configuration": "configuration",
    "Policy": "policy",
    "Procedure": "procedure",
    "Audit Record": "audit-record",
}


def _uuid(*parts):
    """Deterministic UUID5 from stable string parts."""
    return str(uuid.uuid5(_NS, "|".join(str(p) for p in parts)))


def _status_prop(status):
    return {
        "name": "sdr-implementation-status",
        "ns": "https://fedramp.gov/ns/sdr",
        "value": status,
    }


def _finding_for(item, kind):
    """Build one OSCAL finding from an FRR or KSI SDR entry.

    kind is 'requirement' or 'ksi'. Status is passed through verbatim; the
    OSCAL target status is a relabel of the SDR status, never a fresh decision.
    """
    if kind == "ksi":
        sdr_id = item.get("ksiId", "UNKNOWN")
        status = item.get("ksiImplementationStatus", "Not Implemented")
        title = item.get("providerExtensions", {}).get("ksiName", sdr_id)
        impl = item.get("ksiImplementation", [])
    else:
        sdr_id = item.get("frrID", "UNKNOWN")
        status = item.get("frrImplementationStatus", "Not Implemented")
        title = item.get("providerExtensions", {}).get("ruleName", sdr_id)
        impl = item.get("frrImplementation", [])

    description = "\n\n".join(s for s in impl if isinstance(s, str)) or "No implementation statement provided."
    return {
        "uuid": _uuid(kind, sdr_id),
        "title": f"{sdr_id}: {title}",
        "description": description,
        "props": [
            _status_prop(status),
            {"name": "sdr-id", "ns": "https://fedramp.gov/ns/sdr", "value": sdr_id},
            {"name": "sdr-kind", "ns": "https://fedramp.gov/ns/sdr", "value": kind},
        ],
        "target": {
            "type": "objective-id",
            "target-id": sdr_id,
            "status": {"state": _STATUS_TO_OSCAL.get(status, "not-satisfied")},
        },
    }


def _observations_and_resources(ksi):
    """Turn a KSI's ksiEvidence[] into OSCAL observations + back-matter
    resources. Evidence with no evidenceLocation and no evidenceText is skipped
    (a TBD placeholder is not real evidence and is not emitted)."""
    observations = []
    resources = []
    sdr_id = ksi.get("ksiId", "UNKNOWN")
    for i, ev in enumerate(ksi.get("ksiEvidence", []) or []):
        if not isinstance(ev, dict):
            continue
        location = ev.get("evidenceLocation")
        text = ev.get("evidenceText")
        if not location and not text:
            continue  # nothing concrete to point at
        ev_type = ev.get("evidenceType", "Report")
        desc = ev.get("evidenceDescription", f"Evidence for {sdr_id}")
        res_uuid = _uuid("evidence", sdr_id, i, location or text[:40])
        resource = {
            "uuid": res_uuid,
            "title": f"{sdr_id} evidence {i + 1}",
            "description": desc,
            "props": [
                {"name": "type", "value": _EVIDENCE_TYPE.get(ev_type, "report")},
            ],
        }
        if location:
            resource["rlinks"] = [{"href": location}]
        if text:
            # OSCAL base64 field is heavy; keep short evidence text as a citation.
            resource["citation"] = {"text": text[:4000]}
        if ev.get("lastUpdated"):
            resource.setdefault("props", []).append(
                {"name": "last-updated", "value": ev["lastUpdated"]}
            )
        resources.append(resource)

        observations.append({
            "uuid": _uuid("observation", sdr_id, i),
            "title": f"{sdr_id} observation {i + 1}",
            "description": desc,
            "methods": ["EXAMINE"],
            "relevant-evidence": [{"href": f"#{res_uuid}", "description": desc}],
        })
    return observations, resources


def sdr_to_oscal(sdr, timestamp=None):
    """Transform a loaded SDR dict into an OSCAL Assessment Results dict.

    timestamp is optional and only used for the required metadata.last-modified
    field; pass a fixed value in tests for determinism. When omitted, the SDR's
    own metadata.lastUpdated is used so the OSCAL view inherits the SDR's
    deterministic timestamp rather than a wall clock.
    """
    meta_in = sdr.get("metadata", {})
    last_modified = timestamp or meta_in.get("lastUpdated") or "1970-01-01T00:00:00+00:00"
    version = meta_in.get("version", "0.0.0")

    findings = []
    observations = []
    resources = []

    for req in sdr.get("fedRampRequirements", []):
        findings.append(_finding_for(req, "requirement"))
    for ksi in sdr.get("keySecurityIndicators", []):
        findings.append(_finding_for(ksi, "ksi"))
        obs, res = _observations_and_resources(ksi)
        observations.extend(obs)
        resources.extend(res)

    # Carry NIST 800-53 control IDs, if the SDR listed any, as a control
    # selection so control-keyed tools can join on them.
    control_ids = [
        c.get("controlId")
        for c in sdr.get("securityControls", [])
        if isinstance(c, dict) and c.get("controlId")
    ]

    ar_uuid = _uuid("assessment-results", version, last_modified)
    result = {
        "uuid": _uuid("result", version, last_modified),
        "title": "Security Decision Record - assessment results view",
        "description": (
            "OSCAL Assessment Results view derived from the FedRAMP Security "
            "Decision Record. Findings and statuses are passed through from the "
            "SDR verbatim; this view adds no new determinations."
        ),
        "start": last_modified,
        "findings": findings,
    }
    if observations:
        result["observations"] = observations

    oscal = {
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title": "Security Decision Record (OSCAL export)",
                "last-modified": last_modified,
                "version": version,
                "oscal-version": "1.1.2",
                "props": [
                    {
                        "name": "source-format",
                        "ns": "https://fedramp.gov/ns/sdr",
                        "value": "fedramp-security-decision-record",
                    }
                ],
            },
            "import-ap": {"href": "#"},
            "results": [result],
        }
    }
    if control_ids:
        result["reviewed-controls"] = {
            "control-selections": [
                {"include-controls": [{"control-id": cid} for cid in control_ids]}
            ]
        }
    if resources:
        oscal["assessment-results"]["back-matter"] = {"resources": resources}
    return oscal


def export_file(sdr_path, out_path=None):
    """Read an SDR JSON file, write its OSCAL view, return the out path."""
    with open(sdr_path, encoding="utf-8") as f:
        sdr = json.load(f)
    oscal = sdr_to_oscal(sdr)
    if out_path is None:
        base, _ = os.path.splitext(sdr_path)
        out_path = base + ".oscal.json"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(oscal, f, indent=1)
    return out_path


def main(argv):
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if len(argv) > 1:
        targets = argv[1:]
    else:
        targets = sorted(
            p for p in glob.glob(os.path.join(base, "sdr", "json", "sdr-class-*.json"))
            if ".oscal." not in p and "-extensions" not in p
        )
    if not targets:
        print("no SDR JSON files found to export (run build_sdr.py first)")
        return 1
    for sdr_path in targets:
        out = export_file(sdr_path)
        print(f"OSCAL written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
