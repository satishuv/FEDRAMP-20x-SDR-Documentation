# Offline test for the single audit clock (finding F10).
#
# _utc_today() MUST read the UTC calendar day, not the host's local date. The
# regression that guards this has to actually DETECT the local-vs-UTC swap:
# test_mot_continuity passes its own explicit dates and never calls _utc_today(),
# so it cannot catch a mutation of the clock. This test replaces the datetime
# module that _utc_today() imports so that the UTC clock and the local clock
# return provably DIFFERENT calendar days, then asserts _utc_today() returns the
# UTC one. Under the mutation `return _d.date.today()` it returns the local date
# and this test goes RED.
#
# Run: python validation/scripts/test_utc_clock.py

import os
import sys
import types
import datetime as _real_dt

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


# Two provably different calendar days.
_UTC_DAY = _real_dt.date(2026, 1, 2)
_LOCAL_DAY = _real_dt.date(2026, 1, 1)


class _FakeDateTime:
    @staticmethod
    def now(tz=None):
        # A UTC-aware 'now' on the UTC day. .date() yields _UTC_DAY.
        return _real_dt.datetime(2026, 1, 2, 0, 30, tzinfo=_real_dt.timezone.utc)


class _FakeDate:
    @staticmethod
    def today():
        return _LOCAL_DAY


def main():
    # _utc_today() does `import datetime as _d` internally. Inject a stand-in
    # module so its datetime.now(UTC).date() and date.today() diverge; a correct
    # implementation reads the UTC one, a local-clock mutation reads today().
    fake = types.ModuleType("datetime")
    fake.datetime = _FakeDateTime
    fake.date = _FakeDate
    fake.timezone = _real_dt.timezone
    real_mod = sys.modules.get("datetime")
    sys.modules["datetime"] = fake
    try:
        got = sdr._utc_today()
    finally:
        if real_mod is not None:
            sys.modules["datetime"] = real_mod
        else:
            del sys.modules["datetime"]

    check("_utc_today() reads the UTC calendar day, not local", got == _UTC_DAY)
    check("_utc_today() does NOT return the local date", got != _LOCAL_DAY)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: utc_clock ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
