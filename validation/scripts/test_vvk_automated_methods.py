# Adversarial tests for FRC-CSX-VVK automated-method counting.
#
# The Class C requirement is "at least 2 AUTOMATED methods per KSI". The
# official SDR flattens ksiTests to strings, so the count must run on the
# authoring source and must not be satisfiable by "two strings in an array".
#
# Run: python validation/scripts/test_vvk_automated_methods.py

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
from validate_sdr import count_automated_methods  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _auto(mid, cadence="daily"):
    return {"method_id": mid, "method": f"m-{mid}", "automated": True, "cadence": cadence}


def main():
    # Two plain strings: 0 automated (cannot prove automated once flattened).
    n, s, t = count_automated_methods(["test one", "test two"])
    check("two plain strings count 0 automated", n == 0 and s == 2 and t == 2)

    # Two manual structured methods: 0 automated.
    n, _s, _t = count_automated_methods([
        {"method_id": "a", "method": "x", "automated": False},
        {"method_id": "b", "method": "y", "automated": False}])
    check("two manual methods count 0 automated", n == 0)

    # One automated + one manual: 1 automated.
    n, _s, _t = count_automated_methods([_auto("a"), {"method": "y", "automated": False}])
    check("one automated + one manual counts 1", n == 1)

    # Duplicate automated (same method_id): counts once.
    n, _s, _t = count_automated_methods([_auto("a"), _auto("a")])
    check("duplicate automated method_id counts once", n == 1)

    # Duplicate automated (no id, same text): counts once.
    dup = {"method": "identical text", "automated": True}
    n, _s, _t = count_automated_methods([dict(dup), dict(dup)])
    check("duplicate automated by text counts once", n == 1)

    # Two DISTINCT automated methods: 2 -> satisfies Class C.
    n, _s, _t = count_automated_methods([_auto("a"), _auto("b")])
    check("two distinct automated methods count 2", n == 2)

    # Mixed: 2 distinct automated among strings/manual -> 2.
    n, _s, _t = count_automated_methods([
        "narrative", _auto("a"), {"method": "m", "automated": False}, _auto("b")])
    check("two distinct automated among noise count 2", n == 2)

    # Non-list input is safe.
    n, s, t = count_automated_methods(None)
    check("None input returns zeros", (n, s, t) == (0, 0, 0))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: vvk automated methods ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
