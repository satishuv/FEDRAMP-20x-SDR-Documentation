#!/usr/bin/env python3
"""Generate example event-driven Certification Package artifacts.

These are the CR26 artifacts a provider files when an event occurs (or attests
none): the Incident Report (IEC-CSO-*), the Significant Change Notification
(SCN family), and the vulnerability set - Accepted Vulnerability Information,
Vulnerability Detail Report, and Historical VER Activity (VDR/VER families).

Each is generated as an EXAMPLE scaffold, validated against its official
FedRAMP schema. Empty arrays are meaningful per the schemas: they attest
"none this period", not "unknown". Nothing here is a real filing or a
compliance claim; a provider replaces the EXAMPLE values with real ones when an
actual event occurs.

    python validation/scripts/build_events.py

Outputs under package/events/:
    incident-report-example.json
    significant-change-notification-example.json
    accepted-vulnerabilities-example.json
    vulnerability-detail-report-example.json
    historical-ver-activity-example.json
"""

import datetime
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_DIR = os.path.join(BASE, "package", "events")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def build_all(profile):
    cpo_uri = profile.get("certification_package_overview_uri") \
        or "https://example.provider.gov-placeholder/cpo.json"
    # Deterministic period derived from the pinned dataset date, never a run
    # clock, so examples are byte-stable across builds.
    dataset_date = "-".join(profile["dataset_version"].split(".")[:3])
    to_d = datetime.date.fromisoformat(dataset_date)
    from_d = to_d - datetime.timedelta(days=90)
    from_dt = from_d.isoformat() + "T00:00:00Z"
    to_dt = to_d.isoformat() + "T00:00:00Z"

    note = ("EXAMPLE {kind} scaffold. Validated against the official FedRAMP "
            "schema. Empty arrays attest none-this-period. Replace EXAMPLE "
            "values with real data when an actual event occurs. Not a real "
            "filing and not a compliance claim.")

    return {
        "incident-report-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "reportType": "Initial",
            "providerTrackingId": "EXAMPLE-INC-0001",
            "_eventNote": note.format(kind="Incident Report (IEC-CSO-IIR/OIR/FIR)"),
        },
        "significant-change-notification-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "changeType": "Adaptive",
            "changeDescription": (
                "EXAMPLE: describe the significant change here. Adaptive changes "
                "keep the certification; Transformative changes may require "
                "re-certification (SCN family / FRD-CCC)."),
            "_eventNote": note.format(kind="Significant Change Notification (SCN)"),
        },
        "accepted-vulnerabilities-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "reportPeriod": {"from": from_dt, "to": to_dt},
            # Empty array attests no accepted vulnerabilities this period.
            "acceptedVulnerabilities": [],
            "_eventNote": note.format(kind="Accepted Vulnerability Information (VER)"),
        },
        "vulnerability-detail-report-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "reportPeriod": {"from": from_dt, "to": to_dt},
            # Empty array attests no reportable vulnerabilities this period.
            "vulnerabilities": [],
            "_eventNote": note.format(kind="Vulnerability Detail Report (VDR)"),
        },
        "historical-ver-activity-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "generatedAt": to_dt,
            "activeVulnerabilities": [],
            "acceptedVulnerabilities": [],
            "_eventNote": note.format(kind="Historical VER Activity (VER)"),
        },
    }


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no event artifacts are generated.")
        return 1
    artifacts = build_all(profile)
    for fn, doc in artifacts.items():
        dump_json(doc, os.path.join(OUT_DIR, fn))
    print(f"event artifacts written: {len(artifacts)} files under "
          f"{os.path.relpath(OUT_DIR, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
