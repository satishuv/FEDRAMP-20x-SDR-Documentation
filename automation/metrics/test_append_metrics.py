# Offline tests for the metric-history appender. Exercises append_run directly
# with synthetic registry/facts, no files or account. Run:
#   python automation/metrics/test_append_metrics.py

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import append_metrics as am  # noqa: E402

REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {
    "KSI-A": {"services": ["AWS Config"],
              "checks": [{"type": "config_managed_rule", "target": "r1"}]},
    "KSI-B": {"services": ["Amazon GuardDuty"], "checks": []},
}}


def config(ct):
    return {"r1": {"rule": "r1", "compliance_type": ct}}


def guardduty(status):
    return {"guardduty": [{"service": "guardduty", "check": "detector", "status": status}]}


def test_datapoint_counts_passing_and_total():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("COMPLIANT"), {})
    assert dp == {"passing": 1, "total": 1}
    dp2 = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("NON_COMPLIANT"), {})
    assert dp2 == {"passing": 0, "total": 1}


def test_no_observation_yields_no_datapoint():
    # RULE_NOT_DEPLOYED is not an observation, so no datapoint (not a zero).
    assert am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("RULE_NOT_DEPLOYED"), {}) is None


def test_append_is_idempotent_per_day():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1, "same-day re-run must replace, not duplicate"


def test_append_accumulates_across_days():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    am.append_run(hist, REGISTRY, config("NON_COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 2
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2
    # avg of 1.0 and 0.0 = 0.5
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["avg_passing_fraction"] == 0.5


def test_posture_datapoint_for_guardduty_ksi():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-B"], {}, guardduty("ENABLED"))
    assert dp == {"passing": 1, "total": 1}


def test_pruning_drops_old_points():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2024, 1, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    dates = [p["date"] for p in hist["ksis"]["KSI-A"]["series"]]
    assert "2024-01-01" not in dates, "points older than RETAIN_DAYS must be pruned"
    assert "2026-09-06" in dates


def test_30_day_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 7, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    # Only the recent point is inside the 30-day window ending 2026-09-06.
    assert hist["ksis"]["KSI-A"]["last_30_days"]["days_observed"] == 1
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
