#!/usr/bin/env python3
"""Regression tests for the sdr.py CLI subcommands and the adapter scaffold.

Guards the reviewer-facing commands (review, release, diff) and the adapter SDK
against silent breakage. Offline; no network, no dataset mutation.

    python tests/test_cli.py
"""

import inspect
import io
import os
import subprocess
import sys
from contextlib import redirect_stdout

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))

PY = sys.executable
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def run_cli(*args):
    r = subprocess.run([PY, os.path.join(BASE, "sdr.py"), *args],
                       capture_output=True, text=True, cwd=BASE)
    return r.returncode, r.stdout + r.stderr


def test_review():
    code, out = run_cli("review")
    check("review exits 0", code == 0)
    check("review is read-only about approvals",
          "pipeline cannot" in out.lower() or "human act" in out.lower())
    check("review never claims compliance",
          "compliant" not in out.lower().replace("well-formed", ""))


def test_release():
    # `release` now always runs the full validate suite (which includes THIS
    # test), so invoking it here would recurse. Instead assert its contract:
    # the --no-tests escape hatch is gone, and the reproducibility helper exists.
    import sdr as sdrmod
    code_flag, _ = run_cli("release", "--no-tests")
    check("release rejects the removed --no-tests escape", code_flag != 0)
    check("cmd_reproducibility helper exists", hasattr(sdrmod, "cmd_reproducibility"))
    check("cmd_release forces tests on",
          "args.no_tests = False" in inspect.getsource(sdrmod.cmd_release))


def test_diff_no_args():
    code, out = run_cli("diff")
    check("diff (no args) exits 0", code == 0)
    check("diff explains how to produce a comparison",
          "dataset" in out.lower())


def test_diff_rejects_single_path():
    code, _ = run_cli("diff", "only-one.json")
    check("diff rejects a single path", code == 2)


def test_preflight():
    code, out = run_cli("preflight")
    # The template is deliberately unfilled, so preflight must report blockers.
    check("preflight blocks the unfilled template", code == 1)
    check("preflight names submission blockers", "BLOCK" in out)
    check("preflight never claims compliance",
          "not a compliance determination" in out.lower())
    check("preflight cites FRC-APP-FCP freshness", "FRC-APP-FCP" in out)


def test_scaffold():
    import scaffold_adapter as sa
    code = sa.scaffold("Falcon", "crowdstrike")
    check("scaffold names the class from the display", "class FalconAdapter" in code)
    check("scaffold implements collect", "def collect(self, raw)" in code)
    check("scaffold registers the adapter", "register_adapter(FalconAdapter())" in code)
    check("scaffold bakes in the gather-not-decide boundary",
          "not a compliance verdict" in code
          or "A validator evaluates; a human assesses" in code)


def main():
    for t in (test_review, test_release, test_diff_no_args,
              test_diff_rejects_single_path, test_preflight, test_scaffold):
        print(t.__name__)
        t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
