#!/usr/bin/env python3
"""Offline tests for the OSCAL exporter.

No AWS, no network, no third-party deps: builds SDR dicts in memory and checks
the transform. Runs under pytest or directly:
    python automation/exporters/test_oscal_export.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oscal_export as ox  # noqa: E402


def _sdr(**over):
    base = {
        "certificationPackageOverviewUri": "https://example.gov/cpo.json",
        "metadata": {"version": "1.0.0", "lastUpdated": "2026-07-14T00:00:00+00:00",
                     "updateSource": "test"},
        "fedRampRequirements": [
            {
                "frrID": "AFC-CSO-INB",
                "frrImplementationStatus": "Implemented",
                "frrImplementation": ["A monitored FedRAMP inbox is maintained."],
                "providerExtensions": {"ruleName": "Maintain a FedRAMP Security Inbox"},
            }
        ],
        "keySecurityIndicators": [
            {
                "ksiId": "KSI-CNA-01",
                "ksiImplementationStatus": "Not Implemented",
                "ksiImplementation": ["TBD: Information has not been provided."],
                "ksiEvidence": [
                    {
                        "evidenceType": "Configuration",
                        "evidenceDescription": "S3 public access block enabled",
                        "evidenceLocation": "https://evidence.example.gov/s3-pab.json",
                        "lastUpdated": "2026-07-01",
                    },
                    {  # a TBD-only evidence entry must be skipped
                        "evidenceType": "Report",
                        "evidenceDescription": "TBD",
                    },
                ],
                "providerExtensions": {"ksiName": "Cloud Native Architecture"},
            }
        ],
        "securityControls": [{"controlId": "AC-2"}, {"controlId": "SC-7"}],
    }
    base.update(over)
    return base


def test_top_level_shape():
    o = ox.sdr_to_oscal(_sdr())
    assert "assessment-results" in o
    ar = o["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert ar["metadata"]["version"] == "1.0.0"
    # SDR lastUpdated flows into OSCAL last-modified (deterministic, not a clock)
    assert ar["metadata"]["last-modified"] == "2026-07-14T00:00:00+00:00"
    assert len(ar["results"]) == 1


def test_finding_count_and_status_passthrough():
    o = ox.sdr_to_oscal(_sdr())
    result = o["assessment-results"]["results"][0]
    findings = result["findings"]
    assert len(findings) == 2  # 1 FRR + 1 KSI
    by_id = {f["target"]["target-id"]: f for f in findings}

    # Implemented -> satisfied, and the raw SDR status is preserved verbatim
    frr = by_id["AFC-CSO-INB"]
    assert frr["target"]["status"]["state"] == "satisfied"
    assert any(p["name"] == "sdr-implementation-status" and p["value"] == "Implemented"
               for p in frr["props"])

    # Not Implemented -> not-satisfied; never silently upgraded
    ksi = by_id["KSI-CNA-01"]
    assert ksi["target"]["status"]["state"] == "not-satisfied"
    assert any(p["value"] == "Not Implemented" for p in ksi["props"])


def test_evidence_mapped_and_tbd_skipped():
    o = ox.sdr_to_oscal(_sdr())
    ar = o["assessment-results"]
    resources = ar.get("back-matter", {}).get("resources", [])
    # Only the concrete evidence (with a location) becomes a resource; the
    # TBD-only entry is dropped.
    assert len(resources) == 1
    res = resources[0]
    assert res["rlinks"][0]["href"] == "https://evidence.example.gov/s3-pab.json"
    assert any(p["name"] == "type" and p["value"] == "configuration" for p in res["props"])
    # observation references the resource
    obs = o["assessment-results"]["results"][0]["observations"]
    assert len(obs) == 1
    assert obs[0]["relevant-evidence"][0]["href"] == "#" + res["uuid"]


def test_control_ids_carried():
    o = ox.sdr_to_oscal(_sdr())
    result = o["assessment-results"]["results"][0]
    ids = [c["control-id"]
           for sel in result["reviewed-controls"]["control-selections"]
           for c in sel["include-controls"]]
    assert ids == ["AC-2", "SC-7"]


def test_no_evidence_no_backmatter():
    sdr = _sdr(keySecurityIndicators=[{
        "ksiId": "KSI-IAM-01",
        "ksiImplementationStatus": "Not Implemented",
        "ksiImplementation": ["TBD"],
        "ksiEvidence": [],
        "providerExtensions": {"ksiName": "Identity"},
    }])
    o = ox.sdr_to_oscal(sdr)
    assert "back-matter" not in o["assessment-results"]


def test_deterministic_output():
    a = ox.sdr_to_oscal(_sdr())
    b = ox.sdr_to_oscal(_sdr())
    import json
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_no_fabricated_satisfaction():
    """Every finding marked satisfied must trace to an SDR status of
    Implemented. The exporter must never invent satisfaction."""
    o = ox.sdr_to_oscal(_sdr())
    for f in o["assessment-results"]["results"][0]["findings"]:
        state = f["target"]["status"]["state"]
        raw = next(p["value"] for p in f["props"] if p["name"] == "sdr-implementation-status")
        if state == "satisfied":
            assert raw == "Implemented"


def _run_direct():
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_direct())
