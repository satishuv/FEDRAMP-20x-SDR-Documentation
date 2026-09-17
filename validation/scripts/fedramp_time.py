#!/usr/bin/env python3
"""Shared FedRAMP time arithmetic.

FedRAMP states its cadences and windows in CALENDAR MONTHS ("every 3 months",
"within the previous 3 months", "at least the past 6 months") and in some cases
in BUSINESS DAYS (change-notification and incident deadlines), NOT in fixed day
counts. A fixed-day approximation is wrong at the boundary: 2026-06-16 to
2026-09-16 is exactly 3 calendar months but 92 days, so a days=91 or days=90
cutoff misjudges a boundary date.

This module is the single source of that arithmetic. Every generator and gate
(sdr.py preflight, build_ocr.py, build_cpo.py, build_events.py, append_metrics,
and future deadline engines) MUST use these functions rather than
`timedelta(days=90)`-style approximations, so the calendar logic cannot drift
between call sites.

The 7-day FRC-APP-FCP rule intentionally stays in days elsewhere because the
dataset states it in days, not months.
"""

import datetime as _dt


def add_calendar_months(ref, months):
    """The date exactly `months` calendar months after `ref` (a date).

    `months` may be negative to go backwards. The day is clamped to the target
    month's last valid day, e.g. add_calendar_months(date(2026, 5, 31), -3) is
    2026-02-28 (or 02-29 in a leap year) and add_calendar_months(date(2026, 1,
    31), 1) is 2026-02-28.
    """
    if isinstance(ref, _dt.datetime):
        ref = ref.date()
    y = ref.year + (ref.month - 1 + months) // 12
    m = (ref.month - 1 + months) % 12 + 1
    if m == 12:
        last = 31
    else:
        last = (_dt.date(y, m + 1, 1) - _dt.timedelta(days=1)).day
    return _dt.date(y, m, min(ref.day, last))


def months_before(ref, months):
    """The date exactly `months` calendar months BEFORE `ref`.

    Convenience wrapper mirroring the freshness-window semantics used in
    sdr.py preflight ("within the previous N months" -> value must be on or
    after months_before(today, N)).
    """
    return add_calendar_months(ref, -abs(months))


def business_days_after(ref, days):
    """The date `days` business days (Mon-Fri) after `ref`.

    Weekends are skipped; federal holidays are NOT modeled (FedRAMP business-day
    deadlines are counted in business days without a published holiday
    calendar). `days` must be a non-negative integer.
    """
    if isinstance(ref, _dt.datetime):
        ref = ref.date()
    if days < 0:
        raise ValueError("business_days_after requires days >= 0")
    d = ref
    remaining = days
    while remaining > 0:
        d = d + _dt.timedelta(days=1)
        if d.weekday() < 5:  # 0-4 = Mon-Fri
            remaining -= 1
    return d
