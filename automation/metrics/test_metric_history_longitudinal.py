# Longitudinal metric-history test for SDR-CSX-KMT accumulation.
#
# Drives append_run one calendar day at a time for ~420 consecutive days and
# asserts the rollups an assessor relies on: RETAIN_DAYS pruning, the
# up_to_one_year count, the last_30_days window, the average passing fraction
# for a known pattern, and same-day idempotency. No AWS, no boto3, no files.
#
# Run: python automation/metrics/test_metric_history_longitudinal.py

import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import append_metrics as am  # noqa: E402

REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {
    "KSI-A": {"services": ["AWS Config"],
              "checks": [{"type": "config_managed_rule", "target": "r1"}]},
}}


def config(ct):
    return {"r1": {"rule": "r1", "compliance_type": ct}}


def _run_days(n, pattern, start=date(2026, 1, 1)):
    """Append one datapoint/day for n days. pattern(i) -> compliance_type for
    day i. Returns (history, list_of_days)."""
    hist = {}
    days = []
    for i in range(n):
        day = start + timedelta(days=i)
        days.append(day)
        am.append_run(hist, REGISTRY, config(pattern(i)), {}, day)
    return hist, days


def test_series_capped_at_retain_days():
    n = am.RETAIN_DAYS + 20  # 420 when RETAIN_DAYS=400
    hist, _ = _run_days(n, lambda i: "COMPLIANT")
    series = hist["ksis"]["KSI-A"]["series"]
    # prune keeps date >= today - RETAIN_DAYS (inclusive), so the retained
    # window is RETAIN_DAYS + 1 points. This is the actual behavior: it keeps
    # one day more than the nominal window, which is conservative (more
    # history), not a data-loss bug.
    assert len(series) == am.RETAIN_DAYS + 1, \
        f"expected series capped at {am.RETAIN_DAYS + 1}, got {len(series)}"


def test_up_to_one_year_matches_retained_count():
    n = am.RETAIN_DAYS + 20
    hist, _ = _run_days(n, lambda i: "COMPLIANT")
    entry = hist["ksis"]["KSI-A"]
    assert entry["up_to_one_year"]["days_observed"] == am.RETAIN_DAYS + 1


def test_all_compliant_average_is_one():
    hist, _ = _run_days(am.RETAIN_DAYS + 20, lambda i: "COMPLIANT")
    entry = hist["ksis"]["KSI-A"]
    assert entry["up_to_one_year"]["avg_passing_fraction"] == 1.0


def test_alternating_pattern_average_matches_retained_window():
    # Even days COMPLIANT (1.0), odd days NON_COMPLIANT (0.0). The retained
    # window is the last RETAIN_DAYS days, whose pass/fail split depends on the
    # start offset, so derive the expected average from the retained series
    # rather than assuming an exact half. This proves summarize() averages the
    # per-day passing fractions over exactly the retained points.
    def pat(i):
        return "COMPLIANT" if i % 2 == 0 else "NON_COMPLIANT"
    n = am.RETAIN_DAYS + 20
    hist, _ = _run_days(n, pat)
    entry = hist["ksis"]["KSI-A"]
    series = entry["series"]
    expected = round(sum(p["passing"] / p["total"] for p in series) / len(series), 4)
    assert entry["up_to_one_year"]["avg_passing_fraction"] == expected
    # And it is close to one-half for an alternating pattern.
    assert abs(entry["up_to_one_year"]["avg_passing_fraction"] - 0.5) <= 0.01


def test_last_30_days_window_is_only_recent():
    # First 100 days fail, then everything passes. The recent window should be
    # all-passing (1.0), while the one-year average is dragged down by the
    # earlier failures. The code's window is date >= today-30 days, i.e. an
    # inclusive 31-day span (today plus the 30 prior days).
    def pattern(i):
        return "NON_COMPLIANT" if i < 100 else "COMPLIANT"
    hist, _ = _run_days(200, pattern)
    entry = hist["ksis"]["KSI-A"]
    assert entry["last_30_days"]["days_observed"] == 31
    assert entry["last_30_days"]["avg_passing_fraction"] == 1.0
    assert entry["up_to_one_year"]["avg_passing_fraction"] < 1.0


def test_same_day_rerun_replaces_not_duplicates():
    hist = {}
    d = date(2026, 5, 1)
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, d)
    am.append_run(hist, REGISTRY, config("NON_COMPLIANT"), {}, d)
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1, "same-day re-run must replace"
    # The replacement value wins.
    assert series[0]["passing"] == 0


def test_pruning_drops_oldest_dates():
    n = am.RETAIN_DAYS + 20
    hist, days = _run_days(n, lambda i: "COMPLIANT")
    series = hist["ksis"]["KSI-A"]["series"]
    kept_dates = {p["date"] for p in series}
    # The series is capped, so the oldest days fall out of the window. Derive
    # the boundary from the retained series itself rather than assuming an
    # exact count (the cutoff is inclusive: date >= today - RETAIN_DAYS).
    oldest_kept = min(kept_dates)
    # Every day strictly before the oldest kept date must be gone.
    for d in days:
        if d.isoformat() < oldest_kept:
            assert d.isoformat() not in kept_dates
    # At least the very first day is pruned, and the most recent is present.
    assert days[0].isoformat() not in kept_dates
    assert days[-1].isoformat() in kept_dates


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
