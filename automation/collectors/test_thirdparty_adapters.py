#!/usr/bin/env python3
"""Offline tests for the CrowdStrike Falcon and Wiz evidence adapters.

No network, no AWS, no API credentials. Run:
    python automation/collectors/test_thirdparty_adapters.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402
import thirdparty_adapters as tp  # noqa: E402

_EVIDENCE_TYPES = {"Log", "Report", "Screenshot", "Configuration",
                   "Policy", "Procedure", "Audit Record"}


def test_both_adapters_registered():
    assert "crowdstrike-falcon" in ew.list_adapters()
    assert "wiz" in ew.list_adapters()


def test_falcon_maps_to_real_ksis():
    a = ew.get_adapter("crowdstrike-falcon")
    targets = a.ksi_targets()
    # All targets are real KSI ids (family + shape), verified against dataset.
    assert "KSI-MLA-OSM" in targets and "KSI-INR-RIR" in targets
    for t in targets:
        assert t.startswith("KSI-") and len(t) == 11


def test_falcon_export_becomes_hashed_evidence():
    a = ew.get_adapter("crowdstrike-falcon")
    raw = {"observed_at": "2026-09-08T00:00:00Z",
           "sensor_coverage": {"protected": 480, "total": 500},
           "detections_open": 3, "prevention_policy_enabled": True}
    evs = a.to_evidence(raw)
    assert len(evs) == 3
    for ev in evs:
        assert ev["evidenceType"] in _EVIDENCE_TYPES
        assert ev["xEvidenceContentHash"].startswith("sha256:")
    # sensor coverage renders as a percentage
    assert any("96.0%" in ev["evidenceText"] or "96.0%" in ev["evidenceDescription"]
               for ev in evs)


def test_falcon_partial_export_skips_missing_fields():
    a = ew.get_adapter("crowdstrike-falcon")
    evs = a.to_evidence({"observed_at": "2026-09-08T00:00:00Z", "detections_open": 0})
    assert len(evs) == 1
    assert "open_detections" in evs[0]["evidenceText"]


def test_wiz_maps_to_real_ksis():
    a = ew.get_adapter("wiz")
    targets = a.ksi_targets()
    assert "KSI-MLA-EVC" in targets and "KSI-SCR-MON" in targets
    for t in targets:
        assert t.startswith("KSI-") and len(t) == 11


def test_wiz_export_becomes_hashed_evidence():
    a = ew.get_adapter("wiz")
    raw = {"observed_at": "2026-09-08T00:00:00Z",
           "issues_by_severity": {"critical": 0, "high": 2, "medium": 10},
           "config_findings_open": 4, "vulnerabilities_open": 7}
    evs = a.to_evidence(raw)
    assert len(evs) == 3
    for ev in evs:
        assert ev["xEvidenceContentHash"].startswith("sha256:")


def test_adapter_never_sets_status():
    # Attaching adapter evidence to a KSI record touches only `evidence`.
    a = ew.get_adapter("wiz")
    rec = {"implementation_status": "Not Implemented", "implementation": ["TBD"],
           "validation": ["TBD"], "evidence": []}
    facts = list(a.collect({"config_findings_open": 4}))
    ew.attach_evidence(rec, facts)
    assert rec["implementation_status"] == "Not Implemented"
    assert rec["implementation"] == ["TBD"]
    assert len(rec["evidence"]) == 1


def test_opt_in_names_listed():
    assert tp.THIRD_PARTY_ADAPTERS == ["crowdstrike-falcon", "wiz"]


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
