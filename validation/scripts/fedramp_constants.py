#!/usr/bin/env python3
"""Canonical FedRAMP class-keyed constants (FRC-CSX-VVK).

ONE source of truth for the per-class verification-method force and minimums, so
the validators, generators, scanner, metrics, and tests cannot silently disagree
about a MUST vs a SHOULD. These values are verified against the pinned CR26
dataset; changing FedRAMP guidance means changing them HERE, once.

  VVK_FORCE   - force of the automated-verification expectation per class.
  VVK_MINIMUM - minimum number of automated verification methods per class.

Verified anchors: A MAY / 0, B SHOULD / 1, C MUST / 2, D MUST / 4.
"""

# Force of FRC-CSX-VVK per certification class.
VVK_FORCE = {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}

# Minimum automated verification methods per certification class.
VVK_MINIMUM = {"a": 0, "b": 1, "c": 2, "d": 4}


def vvk_force(cls, default="SHOULD"):
    return VVK_FORCE.get((cls or "").lower(), default)


def vvk_minimum(cls, default=None):
    return VVK_MINIMUM.get((cls or "").lower(), default)
