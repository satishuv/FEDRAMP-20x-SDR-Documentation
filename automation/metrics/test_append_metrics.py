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


def test_history_persists_across_ephemeral_runs():
    # Simulate the collector buildspec: each daily run is EPHEMERAL, so it must
    # restore the prior history (from S3), append one datapoint, and persist it.
    # If persistence works, day 2 sees day 1's datapoint; a run that started
    # empty each time (the bug) would only ever hold one point.
    import json
    import tempfile
    store = os.path.join(tempfile.mkdtemp(prefix="mh-"), "metric-history.json")

    # Run 1: no prior history on disk (fresh ephemeral container) -> "restore"
    # finds nothing -> start empty, append, persist.
    hist = am.load(store, {}) or {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist, f, indent=1)

    # Run 2: a NEW ephemeral container restores the persisted history, appends
    # the next day, and persists again.
    hist2 = am.load(store, {}) or {}
    assert hist2.get("ksis"), "run 2 must restore run 1's persisted history"
    am.append_run(hist2, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist2, f, indent=1)

    final = am.load(store, {})
    assert len(final["ksis"]["KSI-A"]["series"]) == 2, \
        "history must accumulate across ephemeral runs, not reset each run"


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


def test_mot_window_class_c_short_and_met():
    today = date(2026, 9, 6)
    # A single point today: 0 days covered, Class C requires 183 -> not met.
    short = am.mot_window([{"date": "2026-09-06", "passing": 1, "total": 1}], "c", today)
    assert short["force"] == "MUST"
    assert short["required_days"] == 183
    assert short["covered_days"] == 0
    assert short["meets_window"] is False
    # A point 200 days ago: covered >= 183 -> met.
    met = am.mot_window([{"date": "2026-02-18", "passing": 1, "total": 1}], "c", today)
    assert met["covered_days"] >= 183
    assert met["meets_window"] is True


def test_mot_window_class_d_needs_18_months():
    today = date(2026, 9, 6)
    w = am.mot_window([{"date": "2025-09-06", "passing": 1, "total": 1}], "d", today)
    # ~365 days covered is short of the 548-day (18 month) Class D requirement.
    assert w["required_days"] == 548
    assert w["meets_window"] is False


def test_mot_window_class_b_is_should_not_gated():
    today = date(2026, 9, 6)
    w = am.mot_window([], "b", today)
    assert w["force"] == "SHOULD"
    assert w["required_days"] == 0
    assert w["meets_window"] is True  # no minimum at B


def test_mot_window_calendar_month_boundary():
    # Regression for the day-approximation bug: a series whose earliest point is
    # exactly 6 CALENDAR months before today must MEET the Class C window, even
    # when that span is fewer than 183 days. 2026-03-16 -> 2026-09-16 is exactly
    # 6 calendar months but only 184 days; pick a span that a days>=183 rule
    # would still pass, and a case a day rule would WRONGLY fail.
    today = date(2026, 9, 16)
    # Exactly 6 calendar months back = 2026-03-16 (184 days) -> meets.
    at_boundary = am.mot_window([{"date": "2026-03-16", "passing": 1, "total": 1}], "c", today)
    assert at_boundary["meets_window"] is True
    # The Feb-boundary case that exposes the bug: today 2026-05-31, 6 months
    # back clamps to 2025-11-30. A point on 2025-11-30 is exactly 6 calendar
    # months (182 days, SHORT of 183) but must still MEET the window.
    today2 = date(2026, 5, 31)
    short_days = am.mot_window([{"date": "2025-11-30", "passing": 1, "total": 1}], "c", today2)
    assert short_days["covered_days"] < 183  # a day rule would call this short
    assert short_days["meets_window"] is True  # calendar months: exactly 6 -> met
    # And a point one day inside the window (later) must FAIL.
    inside = am.mot_window([{"date": "2025-12-01", "passing": 1, "total": 1}], "c", today2)
    assert inside["meets_window"] is False


def test_append_run_records_mot_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6), cls="c")
    w = hist["ksis"]["KSI-A"]["persistent_validation_window"]
    assert w["class"] == "C" and w["force"] == "MUST"


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
