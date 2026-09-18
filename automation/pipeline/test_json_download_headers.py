# Offline tests for the certification-JSON download-header advisory check.
#
# The header set is FedRAMP GUIDANCE (RECOMMENDED, 2026-09-15), NOT a
# Consolidated Rules MUST, so the evaluator only REPORTS presence; gating is the
# caller's --strict choice. These tests exercise the pure evaluator with no
# network.
#
# Run: python automation/pipeline/test_json_download_headers.py

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_json_download_headers import evaluate_headers, main  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _by(results):
    return {r["header"]: r["present"] for r in results}


def main_test():
    # All three present (with a charset on content-type) -> all present.
    r = _by(evaluate_headers({
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": "attachment; filename=cert.json"}))
    check("all three recommended headers detected",
          r["content-type"] and r["x-content-type-options"] and r["content-disposition"])

    # Case-insensitive header names.
    r = _by(evaluate_headers({"content-type": "application/json",
                              "x-content-type-options": "nosniff",
                              "content-disposition": "attachment"}))
    check("lowercase header names detected", all(r.values()))

    # Wrong content-type -> not present.
    r = _by(evaluate_headers({"Content-Type": "text/html",
                              "X-Content-Type-Options": "nosniff",
                              "Content-Disposition": "attachment"}))
    check("text/html content-type is not a match", r["content-type"] is False)

    # nosniff missing -> not present.
    r = _by(evaluate_headers({"Content-Type": "application/json"}))
    check("absent nosniff reported not present", r["x-content-type-options"] is False)
    check("absent content-disposition reported not present", r["content-disposition"] is False)

    # Empty / None input is safe and reports all absent.
    r = _by(evaluate_headers({}))
    check("empty headers -> all absent", not any(r.values()))
    r = _by(evaluate_headers(None))
    check("None headers -> all absent", not any(r.values()))

    # main() with a headers file: default (non-strict) exits 0 even when absent;
    # --strict exits non-zero when a header is absent.
    import json
    import tempfile
    d = tempfile.mkdtemp(prefix="hdr-")
    p = os.path.join(d, "h.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"Content-Type": "text/plain"}, f)
    check("main() non-strict exits 0 on missing headers (advisory)",
          main(["--headers-file", p]) == 0)
    check("main() --strict exits non-zero on missing headers",
          main(["--headers-file", p, "--strict"]) != 0)
    # Full compliant set: strict still exits 0.
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"Content-Type": "application/json", "X-Content-Type-Options": "nosniff",
                   "Content-Disposition": "attachment"}, f)
    check("main() --strict exits 0 when all present",
          main(["--headers-file", p, "--strict"]) == 0)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: json download headers ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main_test())
