#!/usr/bin/env python3
"""F11 regression: the submitted-SDR daily-series window ceiling must be the UTC
calendar day, not the host's local date.today().

Collectors stamp every datapoint with datetime.now(timezone.utc) (UTC). If
build_sdr derives the submitted dailyData / window summaries against the host's
LOCAL date.today(), then on a machine west of UTC near midnight a genuine
current-day UTC observation is dated AFTER the local "today" and is silently
dropped from the submitted SDR (a silent under-report, invisible in UTC CI).
Same two-clock class as F10 (which only fixed sdr.py:_utc_today).

This test injects a stand-in datetime module for the DURATION of the call so
that date.today() (local) reports day 1 while datetime.now(timezone.utc).date()
(UTC) reports day 2 -- a deliberate west-of-UTC-midnight divergence. A datapoint
dated on the UTC day (day 2) MUST survive the window filter. Under the old local
ceiling it is dropped (test RED); under the UTC ceiling it is kept (test GREEN).

    python validation/scripts/test_build_sdr_utc_window.py
"""
import datetime as _real
import os
import sys
import types

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, BASE)

import build_sdr  # noqa: E402

PASS = FAIL = 0

# Two adjacent calendar days: local is a day BEHIND UTC (host west of UTC just
# before its local midnight, while UTC has already ticked over).
LOCAL_DAY = _real.date(2026, 6, 15)
UTC_DAY = _real.date(2026, 6, 16)


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


class _StubDate(_real.date):
    @classmethod
    def today(cls):
        return LOCAL_DAY  # local clock lags UTC


class _StubDateTime(_real.datetime):
    @classmethod
    def now(cls, tz=None):
        # UTC-aware now() lands on the LATER UTC calendar day.
        if tz is not None:
            return _real.datetime(UTC_DAY.year, UTC_DAY.month, UTC_DAY.day,
                                  0, 30, tzinfo=tz)
        # Naive now() follows the lagging local clock.
        return _real.datetime(LOCAL_DAY.year, LOCAL_DAY.month, LOCAL_DAY.day, 23, 30)


def _with_divergent_clock(fn):
    """Run fn() with sys.modules['datetime'] swapped for a stub whose local
    date.today() and UTC datetime.now(tz).date() are one day apart. sdr._utc_today
    does `import datetime as _d` internally, so it picks up the stub; build_sdr's
    local `import datetime as _dd/_ws/_dm` do too."""
    stub = types.ModuleType("datetime")
    stub.date = _StubDate
    stub.datetime = _StubDateTime
    stub.timedelta = _real.timedelta
    stub.timezone = _real.timezone
    saved = sys.modules.get("datetime")
    sys.modules["datetime"] = stub
    try:
        return fn()
    finally:
        if saved is not None:
            sys.modules["datetime"] = saved
        else:
            del sys.modules["datetime"]


def test_current_utc_day_datapoint_survives_derive_daily():
    # A KSI history whose single observation is dated on the UTC day (day 2).
    history = {"ksis": {"KSI-CNA-EIS": {"series": [
        {"date": UTC_DAY.isoformat(), "passing": 5, "total": 5},
    ]}}}
    out = _with_divergent_clock(
        lambda: build_sdr._derive_daily_data("KSI-CNA-EIS", history))
    dates = [str(p.get("date"))[:10] for p in out]
    check("current-day UTC datapoint is retained in the submitted daily series "
          "(not dropped by a lagging local ceiling)",
          UTC_DAY.isoformat() in dates)


def test_window_summary_counts_the_utc_day_datapoint():
    daily = [{"date": UTC_DAY.isoformat(), "passing": 4, "total": 4}]
    last30, year = _with_divergent_clock(
        lambda: build_sdr._window_summaries(daily))
    check("30-day window summary counts the current-day UTC observation",
          isinstance(last30, dict) and last30.get("days_observed") == 1)
    check("1-year window summary counts the current-day UTC observation",
          isinstance(year, dict) and year.get("days_observed") == 1)


def test_per_metric_current_utc_day_survives():
    history = {"ksis": {"KSI-CNA-EIS": {"metrics": {
        "m1": {"objective": "o", "source": "s",
               "series": [{"date": UTC_DAY.isoformat(), "passing": 1, "total": 1}]},
    }}}}
    out = _with_divergent_clock(
        lambda: build_sdr._derive_per_metric("KSI-CNA-EIS", history))
    daily = out[0]["dailyData"] if out else []
    check("per-metric daily series retains the current-day UTC datapoint",
          any(str(p.get("date"))[:10] == UTC_DAY.isoformat() for p in daily))


def main():
    for t in (test_current_utc_day_datapoint_survives_derive_daily,
              test_window_summary_counts_the_utc_day_datapoint,
              test_per_metric_current_utc_day_survives):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
