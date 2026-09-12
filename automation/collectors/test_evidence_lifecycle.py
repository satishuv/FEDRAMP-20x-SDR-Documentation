#!/usr/bin/env python3
"""Offline tests for evidence_lifecycle. No network. Run:
    python automation/collectors/test_evidence_lifecycle.py
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402
import evidence_lifecycle as el  # noqa: E402

NOW = datetime.datetime(2026, 9, 12, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _fact(observed="2026-09-12T11:00:00Z", status="OBSERVED"):
    return {"service": "config", "check": "recorder", "status": status,
            "detail": "on", "region": "us-east-1", "observed_at": observed}


def test_current_within_window():
    s, _ = el.classify_freshness("2026-09-12T11:00:00Z", NOW, 1)
    assert s == "current"


def test_stale_past_window():
    s, _ = el.classify_freshness("2026-09-11T00:00:00Z", NOW, 1)
    assert s == "stale"


def test_expired_beyond_hard_expiry():
    s, _ = el.classify_freshness("2026-09-01T00:00:00Z", NOW, 1)
    assert s == "expired"


def test_missing_when_no_observation():
    s, _ = el.classify_freshness(None, NOW, 1)
    assert s == "missing"


def test_collection_error_short_circuits():
    s, _ = el.classify_freshness("2026-09-12T11:00:00Z", NOW, 1,
                                 collection_status="ERROR:AccessDenied")
    assert s == "collection-error"


def test_lifecycle_record_carries_fields():
    ev = ew.fact_to_evidence(_fact())
    rec = el.lifecycle_record(ev, now=NOW, freshness_policy_days=1,
                              collector="aws-config", collector_version="1.0.0")
    for f in ("evidence_id", "content_hash", "artifact_uri", "expires_at",
              "freshness_status", "collection_status", "review_status"):
        assert f in rec, f"missing lifecycle field {f}"
    assert rec["freshness_status"] == "current"
    assert rec["review_status"] == "unreviewed"


def test_integrity_ok_for_unchanged_fact():
    fact = _fact()
    ev = ew.fact_to_evidence(fact)
    ok, _ = el.verify_integrity(ev, fact)
    assert ok is True


def test_integrity_fails_when_fact_tampered():
    fact = _fact()
    ev = ew.fact_to_evidence(fact)
    tampered = dict(fact, detail="off")  # changed after hashing
    ok, detail = el.verify_integrity(ev, tampered)
    assert ok is False
    assert "integrity-failed" in detail


def test_placeholder_uri_detected():
    ev = ew.fact_to_evidence(_fact())  # no location_base -> placeholder
    assert el.is_placeholder_uri(ev["evidenceLocation"]) is True


def test_collector_health_distinguishes_failure_from_clean():
    ok = el.collector_health("aws-config", last_success="t", objects_collected=83,
                             regions_expected=3, regions_collected=3)
    assert ok["status"] == "complete"
    failed = el.collector_health("aws-config", last_error="AccessDenied")
    assert failed["status"] == "failed"
    degraded = el.collector_health("aws-config", last_success="t",
                                   regions_expected=3, regions_collected=1)
    assert degraded["status"] == "degraded"
    notrun = el.collector_health("aws-config")
    assert notrun["status"] == "not-run"


def test_supersede_keeps_immutable_history():
    e1 = ew.fact_to_evidence(_fact(observed="2026-09-10T11:00:00Z"))
    e2 = ew.fact_to_evidence(_fact(observed="2026-09-11T11:00:00Z"))
    hist = el.supersede([], e1)
    hist = el.supersede(hist, e2)
    assert len(hist) == 2  # old entry retained, not overwritten
    assert hist[-1]["supersedes"] == e1["xEvidenceContentHash"]
    assert hist[0]["supersedes"] is None


def test_adapter_describe_and_health():
    a = ew.get_adapter("csv-count")
    d = a.describe()
    assert d["name"] == "csv-count" and "version" in d and "source_type" in d
    h = a.health()
    assert h["status"] == "not-run"  # default until a real run overrides


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
