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

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: mutation_runner ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
