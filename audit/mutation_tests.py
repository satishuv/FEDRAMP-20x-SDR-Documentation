#!/usr/bin/env python3
"""Mutation tests -- the anti-circular-verification gate (HARD-MODE protocol).

A passing regression test proves nothing if the test cannot actually detect the
defect it claims to guard. This runner RE-INTRODUCES each closed defect into the
PRODUCTION code by textual patch, runs the named regression test, and asserts the
test goes RED. If a mutation SURVIVES (test still green), that is a test-coverage
defect and this runner exits non-zero.

Every mutation restores the file afterward via `git checkout --`, so the tree is
left clean.

    python audit/mutation_tests.py

Mutations that require code only present on an unmerged branch are SKIPPED with a
notice (run them on that branch).
"""
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def _restore(rel):
    subprocess.run(["git", "checkout", "--", rel], cwd=BASE,
                   capture_output=True, text=True)


MUTATIONS = [
    ("MUT-F04",
     "automation/metrics/append_metrics.py",
     'scope = (rule, fact.get("region"), fact.get("account"))',
     'scope = (rule,)  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F01",
     "validation/scripts/validate_evidence.py",
     "    signer_required = bool(trusted_signer",
     "    source, kind = _resolve_source(e)\n    if source is None:\n        return ('finding', 'MUT unverifiable')\n    signer_required = bool(trusted_signer",
     "validation/scripts/test_evidence_integrity.py"),
    ("MUT-F06",
     "sdr.py",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days\n             or leading > max_gap_days)",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days)  # MUTATION",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F05",
     "automation/metrics/append_metrics.py",
     "                          today, cls, require_fresh=True)",
     "                          today, cls, require_fresh=False)  # MUTATION",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F07",
     "automation/metrics/append_metrics.py",
     '    except ValueError as e:\n        return {}, f"metric history is not valid JSON: {e}"',
     '    except ValueError as e:\n        return {}, None  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
]


def run():
    survived, killed, skipped = [], [], []
    for mid, rel, find, repl, test in MUTATIONS:
        path = os.path.join(BASE, rel)
        src = _read(path)
        if find not in src:
            skipped.append(mid)
            print(f"SKIP {mid}: target code not present on this commit")
            continue
        _write(path, src.replace(find, repl, 1))
        try:
            r = subprocess.run([sys.executable, test], cwd=BASE,
                               capture_output=True, text=True, timeout=1800)
        finally:
            _restore(rel)
        if r.returncode != 0:
            killed.append(mid)
            print(f"KILLED {mid}: mutation detected (test red, rc={r.returncode})")
        else:
            survived.append(mid)
            print(f"SURVIVED {mid}: NOT DETECTED -- test-coverage DEFECT")
    print("\n--- mutation summary ---")
    print(f"killed={len(killed)} survived={len(survived)} skipped={len(skipped)}")
    if survived:
        print("FAIL: surviving mutations mean the regression tests are insufficient.")
        return 1
    print("All present mutations detected. Skipped ones must run on their branch.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
