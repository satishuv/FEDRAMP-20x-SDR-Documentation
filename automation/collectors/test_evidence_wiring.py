#!/usr/bin/env python3
"""Offline tests for evidence_wiring.

No AWS, no network. Runs under pytest or directly:
    python automation/collectors/test_evidence_wiring.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402

# The official SDR evidence schema enum, reproduced so the test is self-contained.
_EVIDENCE_TYPES = {"Log", "Report", "Screenshot", "Configuration",
                   "Policy", "Procedure", "Audit Record"}


def _fact(service="s3", check="public_access_block", status="OBSERVED",
          detail="All buckets block public access", region="us-east-1",
          observed_at="2026-09-08T12:00:00+00:00"):
    return {"service": service, "check": check, "status": status,
            "detail": detail, "region": region, "observed_at": observed_at}


def test_fact_becomes_valid_evidence():
    ev = ew.fact_to_evidence(_fact())
    assert ev["evidenceType"] in _EVIDENCE_TYPES
    assert ev["evidenceType"] == "Configuration"  # s3 -> Configuration
    assert "s3:public_access_block" in ev["evidenceDescription"]
    assert ev["evidenceLocation"]
    assert ev["lastUpdated"] == "2026-09-08"  # date only, not datetime


def test_error_fact_is_not_evidence():
    assert ew.fact_to_evidence(_fact(status="ERROR:AccessDenied")) is None


def test_placeholder_is_honest_not_fake_https():
    ev = ew.fact_to_evidence(_fact())
    # With no real store base, the pointer must be an obvious placeholder,
    # never a fabricated https URL implying a real artifact.
    assert ev["evidenceLocation"].startswith("sdr://placeholder/")
    assert not ev["evidenceLocation"].startswith("http")


def test_real_location_base_produces_concrete_uri():
    ev = ew.fact_to_evidence(_fact(), location_base="https://evidence.example.gov/store")
    assert ev["evidenceLocation"] == \
        "https://evidence.example.gov/store/s3/public_access_block/us-east-1.json"


def test_cloudtrail_maps_to_audit_record():
    ev = ew.fact_to_evidence(_fact(service="cloudtrail", check="trail_status"))
    assert ev["evidenceType"] == "Audit Record"


def test_attach_does_not_touch_status():
    rec = {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD"],
        "validation": ["TBD"],
        "assessment": ["TBD"],
        "evidence": [],
    }
    before = dict(rec)
    added = ew.attach_evidence(rec, [_fact(), _fact(service="config", check="recorder")])
    assert added == 2
    # every non-evidence field is byte-identical
    assert rec["implementation_status"] == before["implementation_status"]
    assert rec["implementation"] == before["implementation"]
    assert rec["validation"] == before["validation"]
    assert rec["assessment"] == before["assessment"]
    assert len(rec["evidence"]) == 2


def test_attach_dedupes_by_location():
    rec = {"evidence": []}
    ew.attach_evidence(rec, [_fact()])
    added = ew.attach_evidence(rec, [_fact()])  # same fact again
    assert added == 0
    assert len(rec["evidence"]) == 1


def test_attach_replace_mode():
    rec = {"evidence": [{"evidenceLocation": "sdr://placeholder/old", "evidenceType": "Report"}]}
    ew.attach_evidence(rec, [_fact()], replace=True)
    assert len(rec["evidence"]) == 1
    assert rec["evidence"][0]["evidenceType"] == "Configuration"


def test_error_facts_dropped_in_bulk():
    facts = [_fact(), _fact(status="ERROR:Timeout"), _fact(service="config")]
    out = ew.facts_to_evidence(facts)
    assert len(out) == 2


def _run_direct():
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_direct())
