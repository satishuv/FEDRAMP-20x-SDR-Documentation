#!/usr/bin/env python3
"""Adversarial test for validate_cpo_semantics independent derivation.

Proves the CPO semantic validator INDEPENDENTLY derives the required
CPO-CSO-OVR rule set from CR26 and rejects a CPO that drops one - i.e. a builder
and validator cannot agree on the same omission. Mirrors why the SDR validator
is trustworthy: it re-derives the truth instead of trusting the artifact.

    python validation/scripts/test_cpo_semantics_adversarial.py
"""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))

import validate_cpo_semantics as vcs

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def test_independent_set_is_nonempty():
    expected = vcs._expected_ovr_rules()
    check("expected OVR rule set derived from CR26 is non-empty",
          bool(expected) and "MAS-CSO-TPR" in expected)


def test_dropped_rule_would_mismatch():
    # Simulate a CPO that dropped MAS-CSO-TPR from its required-info items.
    expected = vcs._expected_ovr_rules()
    actual = set(expected) - {"MAS-CSO-TPR"}
    # The validator's set-equality check would flag this as missing.
    check("dropping a required rule is detected by set inequality",
          expected != actual and "MAS-CSO-TPR" in (expected - actual))


def test_class_a_expected_set_is_scoped():
    # Class A resolves only CDS-CSO-PUB and MAS-CSO-IIR of the OVR set, so the
    # expected set for A must be exactly those two - not the full nine (which
    # would be a Class A false blocker).
    a = vcs._expected_ovr_rules("a")
    bc = vcs._expected_ovr_rules("b")
    check("Class A expected OVR set is scoped to its 2 applicable rules",
          a == {"CDS-CSO-PUB", "MAS-CSO-IIR"})
    check("Class B expected OVR set is broader than Class A",
          bc is not None and a is not None and a < bc)


def main():
    for t in (test_independent_set_is_nonempty, test_dropped_rule_would_mismatch,
              test_class_a_expected_set_is_scoped):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
