#!/usr/bin/env python3
"""Test the third-party evidence upsert (replace-on-change) semantics.

Third-party evidence at a stable location must UPSERT: a newer observation
(changed content hash or later timestamp) replaces the stale entry rather than
being skipped, and an identical observation does not duplicate.

    python automation/collectors/test_thirdparty_upsert.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import apply_third_party_evidence as ap  # noqa: E402


def main():
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    loc = "https://falcon.example/evidence/1"
    old = {"evidenceLocation": loc, "xEvidenceContentHash": "sha256:" + "a" * 64,
           "collected_at": "2026-09-01T00:00:00+00:00"}
    newer = {"evidenceLocation": loc, "xEvidenceContentHash": "sha256:" + "b" * 64,
             "collected_at": "2026-09-08T00:00:00+00:00"}
    same = dict(old)

    check("a changed observation is newer", ap._is_newer(newer, old) is True)
    check("an identical observation is not newer", ap._is_newer(same, old) is False)
    check("an older observation does not replace",
          ap._is_newer(old, newer) is False)

    print(f"\n{passed}/{passed + failed} third-party upsert checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
