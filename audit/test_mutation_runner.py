#!/usr/bin/env python3
"""Regression for the mutation runner itself: a stale bytecode cache must never
turn a real mutation into a false SURVIVED.

The trap (seen on main, validate-sdr run 35993242564): Python trusts a cached
__pycache__/*.pyc when the source's SIZE and mtime-in-seconds match its header.
MUT-F10's replacement is exactly as long as the text it replaces, so the mutated
sdr.py has the original's size; when it also lands in the same wall-clock second
as a pyc compiled from the ORIGINAL, the interpreter runs the original bytecode
and test_utc_clock.py passes against unmutated code.

This test arms that trap deliberately, PROVES it is armed (a bare run of the
regression test is fooled, rc=0), then asserts the runner's run_one() still
reports the mutation KILLED. Under the pre-fix runner (no cache purge) the second
assertion fails, so this test is itself mutation-verified.

    python audit/test_mutation_runner.py
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mutation_tests as mt  # noqa: E402

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def _entry(mid):
    for m in mt.MUTATIONS:
        if m[0] == mid:
            return m
    raise KeyError(mid)


def _compile_original(module_dir, module):
    """Compile module from the CURRENT source into __pycache__ (pyc writes
    explicitly allowed, whatever the ambient environment says)."""
    env = dict(os.environ)
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    r = subprocess.run([sys.executable, "-c", f"import {module}"], cwd=module_dir,
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)


def main():
    mid, rel, find, repl, test = _entry("MUT-F10")
    path = os.path.join(BASE, rel)
    module_dir = os.path.dirname(path)
    module = os.path.splitext(os.path.basename(path))[0]

    original = mt._read(path)
    original_bytes = mt._read_bytes(path)
    check("fixture: mutation target present in source", original.count(find) == 1)
    check("fixture: replacement preserves source length (the trap needs it)",
          len(find) == len(repl), f"{len(find)} vs {len(repl)}")
    mutated = original.replace(find, repl, 1)

    try:
        # 1. Cache the ORIGINAL bytecode, recording the original's size + mtime.
        shutil.rmtree(os.path.join(module_dir, "__pycache__"), ignore_errors=True)
        _compile_original(module_dir, module)
        pyc_dir = os.path.join(module_dir, "__pycache__")
        check("fixture: original bytecode cached", os.path.isdir(pyc_dir)
              and any(n.startswith(module + ".") for n in os.listdir(pyc_dir)))
        st = os.stat(path)

        # 2. Write the mutation, then pin the mtime back to the original's so
        #    the header still matches (same size, same second).
        mt._write(path, mutated)
        os.utime(path, (st.st_atime, st.st_mtime))
        st2 = os.stat(path)
        check("fixture: mutated file has identical size and mtime-second",
              st2.st_size == st.st_size and int(st2.st_mtime) == int(st.st_mtime))

        # 3. PROVE the trap is armed: a bare test run is fooled by the cache.
        bare = subprocess.run([sys.executable, test], cwd=BASE,
                              capture_output=True, text=True, timeout=600)
        check("trap armed: bare regression run is fooled by stale bytecode (rc=0)",
              bare.returncode == 0, f"rc={bare.returncode}")
    finally:
        mt._restore(rel, original_bytes)
    check("fixture: trap cleaned up byte-exactly", mt._read_bytes(path) == original_bytes)

    # 4. The runner must not be fooled. run_one re-applies the mutation itself;
    #    re-arm the cache so it faces the same trap the bare run did.
    _compile_original(module_dir, module)
    st = os.stat(path)
    outcome = None
    try:
        # Freeze the clock the runner's _write will see: patch _write so the
        # mutated file keeps the original's mtime, exactly as the CI race did.
        real_write = mt._write

        def pinned_write(p, s):
            real_write(p, s)
            os.utime(p, (st.st_atime, st.st_mtime))

        mt._write = pinned_write
        outcome = mt.run_one(mid, rel, find, repl, test)
    finally:
        mt._write = real_write
        mt._restore(rel, original_bytes)
        shutil.rmtree(os.path.join(module_dir, "__pycache__"), ignore_errors=True)

    check("runner kills the mutation through the stale-cache trap",
          outcome == "killed", f"outcome={outcome}")
    check("tree restored byte-exactly", mt._read_bytes(path) == original_bytes)

    # --- AUD-F13: a SKIPPED mutation must FAIL the gate, not pass it. -----------
    # A mutation whose target text is absent never executes. run_one returns
    # 'skipped' before touching the file, so this is side-effect free.
    absent = ("MUT-SELFTEST-ABSENT", rel,
              "# this exact text is not present in sdr.py anywhere at all",
              "# MUTATION", test)
    synthetic_ledger = {"defects": [
        {"id": "AUD-SELFTEST", "status": "CLOSED", "mutation_verified": True,
         "mutation": "MUT-SELFTEST-ABSENT: absent target; expect RED"}]}
    rc_skip = mt.run(mutations=[absent], ledger=synthetic_ledger)
    check("F13: a skipped mutation fails the gate end-to-end (rc != 0)", rc_skip != 0,
          f"rc={rc_skip}")
    # Isolated rule: a skip alone (no survivors, no ledger problems) must fail.
    check("F13: gate_verdict fails on a skip alone",
          mt.gate_verdict([], ["MUT-X"], []) != 0)
    check("F13 control: gate_verdict passes with nothing wrong",
          mt.gate_verdict([], [], []) == 0)
    check("F13 control: gate_verdict fails on a survivor alone",
          mt.gate_verdict(["MUT-X"], [], []) != 0)
    check("F14: gate_verdict fails on a ledger problem alone",
          mt.gate_verdict([], [], ["x"]) != 0)

    # --- AUD-F14: the ledger must reconcile with what the runner executed. -----
    def problems(outcomes, mutations, ledger):
        return mt.reconcile_ledger(outcomes, mutations=mutations, ledger=ledger)

    one = [("MUT-X", "sdr.py", "a", "b", "t.py")]
    ledger_x = {"defects": [{"id": "AUD-X", "status": "CLOSED",
                             "mutation_verified": True,
                             "mutation": "MUT-X: something; expect RED"}]}
    check("F14: killed + ledgered + single entry reconciles clean",
          problems({"MUT-X": "killed"}, one, ledger_x) == [])
    check("F14: ledger claims a mutation the runner does not contain -> problem",
          any("no such mutation" in p for p in problems(
              {}, [], ledger_x)))
    check("F14: runner entry with no ledger defect -> problem (unledgered)",
          any("unledgered" in p for p in problems(
              {"MUT-X": "killed"}, one, {"defects": []})))
    check("F14: ledgered mutation that survived -> problem",
          any("must be 'killed'" in p for p in problems(
              {"MUT-X": "survived"}, one, ledger_x)))
    check("F14: ledgered mutation that was skipped -> problem",
          any("must be 'killed'" in p for p in problems(
              {"MUT-X": "skipped"}, one, ledger_x)))
    check("F14: duplicate runner ids -> problem",
          any("exactly one" in p for p in problems(
              {"MUT-X": "killed"}, one + one, ledger_x)))
    check("F14: REVIEWED-NO-CHANGE entries are not required to have a mutation",
          problems({"MUT-X": "killed"}, one, {"defects": ledger_x["defects"] + [
              {"id": "AUD-C0", "status": "REVIEWED-NO-CHANGE",
               "mutation_verified": False, "mutation": "n/a"}]}) == [])
    # The REAL ledger and the REAL runner list must agree structurally (every
    # claimed id has exactly one entry, every entry is claimed) before any run.
    with open(mt.LEDGER, encoding="utf-8") as f:
        real_ledger = __import__("json").load(f)
    structural = [p for p in problems(
        {m[0]: "killed" for m in mt.MUTATIONS}, mt.MUTATIONS, real_ledger)]
    check("F14: real ledger and real runner list agree structurally",
          structural == [], "; ".join(structural))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: mutation_runner ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
