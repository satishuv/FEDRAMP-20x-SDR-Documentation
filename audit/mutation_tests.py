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

Bytecode cache. Python validates a cached `__pycache__/*.pyc` by source SIZE and
source mtime in WHOLE SECONDS only. A mutation whose replacement has the same
length as the text it replaces (MUT-F10 is exactly 50 -> 50 characters) leaves
the size unchanged, so if an earlier step compiled the ORIGINAL module and the
mutated file lands in the same wall-clock second, the interpreter loads the
original bytecode and the regression "passes" against unmutated code. That is a
false SURVIVED that has nothing to do with the test. CI hit it on main twice
(validate-sdr run 35993242564). The runner therefore purges every __pycache__
before each mutated test run and forbids pyc writes during it
(PYTHONDONTWRITEBYTECODE), so a test can only ever exercise the source on disk.
`-B` alone is NOT enough: it stops writing pycs but still READS a stale one.
"""
import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def _read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _restore(rel, original_bytes=None):
    """Put the committed source back. When the caller saved the original bytes,
    write them back FIRST: `git checkout --` trusts its stat cache, and a
    size-preserving mutation that lands in the original's mtime second can look
    unchanged to it and be left in place. Then verify, loudly."""
    path = os.path.join(BASE, rel)
    if original_bytes is not None:
        with open(path, "wb") as f:
            f.write(original_bytes)
    subprocess.run(["git", "checkout", "--", rel], cwd=BASE,
                   capture_output=True, text=True)
    if original_bytes is not None and _read_bytes(path) != original_bytes:
        raise RuntimeError(f"restore of {rel} failed: working tree still differs "
                           "from the saved original")


def _purge_bytecode(root=BASE):
    """Remove every __pycache__ under root so no cached bytecode can stand in
    for the source on disk. .git is skipped; nothing there is ours to touch."""
    for dirpath, dirnames, _files in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        if "__pycache__" in dirnames:
            shutil.rmtree(os.path.join(dirpath, "__pycache__"), ignore_errors=True)
            dirnames.remove("__pycache__")


def _no_bytecode_env():
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


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
    ("MUT-F02",
     "validation/scripts/verification_methods.py",
     "            if not ident:\n                # F02: an automated method with no method_id is uncountable and\n                # unbindable; surface it informationally, do not count it.\n                strings += 1\n                continue",
     "            if not ident:\n                seen.add(str(id(t)))  # MUTATION count id-less automated\n                continue",
     "validation/scripts/test_vvk_automated_methods.py"),
    ("MUT-F03",
     "automation/metrics/append_metrics.py",
     '            if check_filter and pf.get("check") != check_filter:\n                continue  # F03: check-scoped key rejects other checks',
     '            if False:  # MUTATION drop check filter\n                continue',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F08",
     "automation/collectors/collectors.py",
     '            if "ServerSideEncryptionConfigurationNotFound" in name:\n                checked += 1  # evaluated: no encryption configured\n            else:\n                unmeasured += 1',
     '            checked += 1  # MUTATION count any error as evaluated\n            if False:\n                unmeasured += 1',
     "automation/collectors/test_collectors.py"),
    ("MUT-F09",
     "automation/collectors/collectors.py",
     '        if more:',
     '        if False:  # MUTATION ignore bounded-sample partial',
     "automation/collectors/test_collectors.py"),
    ("MUT-F10",
     "sdr.py",
     "    return _d.datetime.now(_d.timezone.utc).date()",
     "    return _d.date.today()  # MUTATION local clock",
     "validation/scripts/test_utc_clock.py"),
    ("MUT-F11",
     "validation/scripts/build_sdr.py",
     "    _u = _utc_today()\n    cutoff = (_u - _dd.timedelta(days=365)).isoformat()\n    _today = _u.isoformat()",
     "    cutoff = (_dd.date.today() - _dd.timedelta(days=365)).isoformat()  # MUTATION local clock\n    _today = _dd.date.today().isoformat()",
     "validation/scripts/test_build_sdr_utc_window.py"),
]


def run_one(mid, rel, find, repl, test):
    """Apply one mutation, run its regression test against the source on disk,
    restore. Returns 'killed', 'survived' or 'skipped'."""
    path = os.path.join(BASE, rel)
    original_bytes = _read_bytes(path)
    src = _read(path)
    if find not in src:
        print(f"SKIP {mid}: target code not present on this commit")
        return "skipped"
    _write(path, src.replace(find, repl, 1))
    try:
        # No cached bytecode may answer for the mutated source (see module doc).
        _purge_bytecode()
        r = subprocess.run([sys.executable, test], cwd=BASE, env=_no_bytecode_env(),
                           capture_output=True, text=True, timeout=1800)
    finally:
        _restore(rel, original_bytes)
        _purge_bytecode()
    if r.returncode != 0:
        print(f"KILLED {mid}: mutation detected (test red, rc={r.returncode})")
        return "killed"
    print(f"SURVIVED {mid}: NOT DETECTED -- test-coverage DEFECT")
    return "survived"


def run():
    survived, killed, skipped = [], [], []
    for mid, rel, find, repl, test in MUTATIONS:
        outcome = run_one(mid, rel, find, repl, test)
        {"killed": killed, "survived": survived, "skipped": skipped}[outcome].append(mid)
    print("\n--- mutation summary ---")
    print(f"killed={len(killed)} survived={len(survived)} skipped={len(skipped)}")
    if survived:
        print("FAIL: surviving mutations mean the regression tests are insufficient.")
        return 1
    print("All present mutations detected. Skipped ones must run on their branch.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
