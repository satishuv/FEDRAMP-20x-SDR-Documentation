#!/usr/bin/env python3
"""Invariant: every service a production collector emits must be either routed
downstream (present in the canonical service registry) or explicitly marked
telemetry-only. This prevents the collector -> prefill/AI routing drift where a
newly collected service is silently unrouted.

    python automation/collectors/test_service_registry.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import service_registry as sr  # noqa: E402

COLLECTORS = os.path.join(HERE, "collectors.py")


def emitted_services():
    """Every distinct service name passed as the first arg to _fact(...)."""
    src = open(COLLECTORS, encoding="utf-8").read()
    return set(re.findall(r'_fact\(\s*"([a-z0-9]+)"', src))


def main():
    emitted = emitted_services()
    routed = set(sr.SERVICE_DISPLAY_NAMES)
    telemetry_only = set(sr.TELEMETRY_ONLY_SERVICES)
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    check("collectors emit a non-trivial set of services", len(emitted) >= 10)
    unrouted = sorted(emitted - routed - telemetry_only)
    check("every collector-emitted service is routed or telemetry-only",
          not unrouted)
    if unrouted:
        print(f"    unrouted services: {unrouted} "
              "(add to SERVICE_DISPLAY_NAMES or TELEMETRY_ONLY_SERVICES)")
    # The registry must not claim to route a service the collectors never emit.
    stale = sorted(routed - emitted)
    check("registry does not route phantom (non-emitted) services", not stale)
    if stale:
        print(f"    registry lists services no collector emits: {stale}")

    print(f"\n{passed}/{passed + failed} service-registry invariant checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
