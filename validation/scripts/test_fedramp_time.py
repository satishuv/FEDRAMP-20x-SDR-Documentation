#!/usr/bin/env python3
"""Tests for the shared FedRAMP time arithmetic.

Covers the exact boundary cases a fixed-day approximation gets wrong:
month-end clamping, leap years, and the 3-calendar-month vs 90/91/92-day
distinction that motivated centralizing this logic.

    python validation/scripts/test_fedramp_time.py
"""

import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fedramp_time import add_calendar_months, months_before, business_days_after

_D = datetime.date


def main():
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    # 3 calendar months, not 90 days. 2026-06-16 + 3 months = 2026-09-16
    # (exactly 3 calendar months = 92 days, so a days=90 anchor is wrong).
    check("add 3 months lands on the same day-of-month",
          add_calendar_months(_D(2026, 6, 16), 3) == _D(2026, 9, 16))
    check("3 calendar months is not 90 days at this boundary",
          (add_calendar_months(_D(2026, 6, 16), 3) - _D(2026, 6, 16)).days == 92)

    # Month-end clamping: 3 months before May 31 is Feb 28 (non-leap).
    check("month-end clamps to Feb 28 in a non-leap year",
          add_calendar_months(_D(2026, 5, 31), -3) == _D(2026, 2, 28))
    # Leap year: 3 months before May 31, 2024 is Feb 29.
    check("month-end clamps to Feb 29 in a leap year",
          add_calendar_months(_D(2024, 5, 31), -3) == _D(2024, 2, 29))
    # Jan 31 + 1 month clamps to Feb 28.
    check("Jan 31 + 1 month clamps to Feb 28",
          add_calendar_months(_D(2026, 1, 31), 1) == _D(2026, 2, 28))

    # Year rollover both directions.
    check("cross-year forward (Nov + 3 months = next Feb)",
          add_calendar_months(_D(2026, 11, 15), 3) == _D(2027, 2, 15))
    check("cross-year backward (Feb - 3 months = prior Nov)",
          add_calendar_months(_D(2026, 2, 15), -3) == _D(2025, 11, 15))

    # months_before mirrors the freshness-window semantics.
    check("months_before(x, 6) equals add_calendar_months(x, -6)",
          months_before(_D(2026, 9, 6), 6) == add_calendar_months(_D(2026, 9, 6), -6))
    check("months_before treats sign as magnitude",
          months_before(_D(2026, 9, 6), 6) == months_before(_D(2026, 9, 6), -6))

    # datetime input is accepted (coerced to date).
    check("datetime input is coerced to date",
          add_calendar_months(datetime.datetime(2026, 6, 16, 13, 0), 3) == _D(2026, 9, 16))

    # business_days_after skips weekends. Fri 2026-09-04 + 3 business days =
    # Wed 2026-09-09 (skips Sat/Sun).
    check("3 business days after a Friday skips the weekend",
          business_days_after(_D(2026, 9, 4), 3) == _D(2026, 9, 9))
    check("0 business days is the same day",
          business_days_after(_D(2026, 9, 4), 0) == _D(2026, 9, 4))
    check("5 business days after Monday is the next Monday",
          business_days_after(_D(2026, 9, 7), 5) == _D(2026, 9, 14))
    try:
        business_days_after(_D(2026, 9, 4), -1)
        neg_raised = False
    except ValueError:
        neg_raised = True
    check("business_days_after rejects negative days", neg_raised)

    print(f"\n{passed}/{passed + failed} fedramp_time checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
