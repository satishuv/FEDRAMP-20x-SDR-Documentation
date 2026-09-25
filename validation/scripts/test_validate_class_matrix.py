#!/usr/bin/env python3
"""Class-matrix validation (AUD-F23) and validator report contract (AUD-F24).

The repository ships Class A, B and C artifacts but the authoritative validator
used to run only against the offering profile's class, so the inactive classes
had weaker checks; when first run against Class C, the committed template
failed two MUST-level checks (three populated example KSIs with plain-string
tests and no evidence). This test asserts the override exists and behaves:
SDR_VALIDATE_CLASS=a validates the Class A artifacts, writes its reports under
the gitignored matrix directory, leaves the canonical active-class reports
untouched, and `sdr.py validate` drives the matrix for every inactive class. It
also pins the validator's report shape ("results"), which a parity test once
misread as "ksi_results" and therefore compared 0 against 0.

    python validation/scripts/test_validate_class_matrix.py
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
REPORTS = os.path.join(BASE, "validation", "reports")
_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def main():
    offering = json.load(open(os.path.join(BASE, "profiles", "common", "offering-profile.json"),
                              encoding="utf-8"))
    active = offering["certification_class"].lower()
    inactive = [c for c in ("a", "b", "c") if c != active]
    canon = os.path.join(REPORTS, "validation-report.json")
    canon_before = open(canon, "rb").read() if os.path.exists(canon) else None

    import shutil
    for cls in inactive:
        # Start from nothing: a stale matrix report from an earlier run must not
        # be able to satisfy the checks below (that is how a validator that
        # ignored the override once slipped past this test).
        shutil.rmtree(os.path.join(REPORTS, "matrix", f"class-{cls}"), ignore_errors=True)
        env = dict(os.environ, SDR_VALIDATE_CLASS=cls)
        r = subprocess.run([sys.executable, os.path.join(HERE, "validate_sdr.py")],
                           cwd=BASE, env=env, capture_output=True, text=True, timeout=600)
        fails = [ln for ln in r.stdout.splitlines() if ln.startswith("FAIL:")]
        check(f"class {cls.upper()} artifacts pass the authoritative validator",
              r.returncode == 0, "; ".join(fails[:3]) or r.stderr[-300:])
        rep_path = os.path.join(REPORTS, "matrix", f"class-{cls}", "validation-report.json")
        check(f"class {cls.upper()} report written under the matrix directory",
              os.path.exists(rep_path))
        if os.path.exists(rep_path):
            rep = json.load(open(rep_path, encoding="utf-8"))
            check(f"class {cls.upper()} report is stamped with class {cls.upper()}",
                  rep.get("class") == cls.upper(), str(rep.get("class")))
        res_path = os.path.join(REPORTS, "matrix", f"class-{cls}", "ksi-test-results.json")
        if os.path.exists(res_path):
            res = json.load(open(res_path, encoding="utf-8"))
            # AUD-F24: the per-KSI list lives under "results" and is non-empty.
            check(f"class {cls.upper()} ksi-test-results carries a non-empty 'results' list",
                  isinstance(res.get("results"), list) and len(res["results"]) > 0,
                  f"keys={sorted(res)}")

    canon_after = open(canon, "rb").read() if os.path.exists(canon) else None
    check("canonical active-class report is untouched by matrix runs",
          canon_before == canon_after)

    sdr_src = open(os.path.join(BASE, "sdr.py"), encoding="utf-8").read()
    m = re.search(r"^def cmd_validate\(.*?(?=^def )", sdr_src, re.MULTILINE | re.DOTALL)
    body = m.group(0) if m else ""
    check("sdr.py validate drives the class matrix via SDR_VALIDATE_CLASS",
          "SDR_VALIDATE_CLASS" in body and 'for cls in ("a", "b", "c")' in body)
    gi = open(os.path.join(BASE, ".gitignore"), encoding="utf-8").read()
    check("matrix reports are gitignored", "validation/reports/matrix/" in gi)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: class matrix ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
