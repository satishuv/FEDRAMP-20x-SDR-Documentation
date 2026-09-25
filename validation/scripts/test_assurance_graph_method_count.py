# Regression test for F-09: the reviewer-facing assurance graph / evidence
# coverage report must count FRC-CSX-VVK automated methods identically to the
# authoritative validator. A prior bug counted raw `tests` entries in the graph
# (len(tests)) while the validator counted distinct AUTOMATED methods, so the
# reviewer report claimed the minimum was met (3/41) when the authoritative gate
# said it was not (0/41). This test locks the two together.
#
# Run: python validation/scripts/test_assurance_graph_method_count.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))

import validate_sdr  # noqa: E402
import build_assurance_graph  # noqa: E402
from verification_methods import count_automated_methods  # noqa: E402

GRAPH = os.path.join(BASE, "traceability", "assurance-graph.json")
COVERAGE = os.path.join(BASE, "validation", "reports", "evidence-coverage.json")
KSI_RESULTS = os.path.join(BASE, "validation", "reports", "ksi-test-results.json")

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    # 1. Both scripts bind the SAME function object, not two copies. If someone
    #    reintroduces an independent len(tests) counter this fails.
    check("validate_sdr uses shared count_automated_methods",
          validate_sdr.count_automated_methods is count_automated_methods)
    check("build_assurance_graph uses shared count_automated_methods",
          build_assurance_graph.count_automated_methods is count_automated_methods)

    # 2. The graph must NOT count raw test entries. A KSI with two plain-string
    #    tests and zero structured automated methods must report 0, not 2.
    n, s, _t = count_automated_methods(["a string test", "another string test"])
    check("two string tests -> 0 automated, 2 unclassified", n == 0 and s == 2)

    if not (os.path.exists(GRAPH) and os.path.exists(COVERAGE)):
        print("  SKIP committed-artifact checks (generate the package first)")
        print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: assurance graph method count "
              f"({_fail} failures)")
        return 1 if _fail else 0

    # Regenerate the validator's report right here so this parity check reads
    # the CURRENT validator's output, not whatever an earlier (possibly
    # adversarial, tampering) test left on disk (AUD-F24). Written to a temp
    # directory so the committed canonical reports are never rewritten by a test.
    import subprocess
    import tempfile
    tmp_reports = tempfile.mkdtemp(prefix="sdr-parity-")
    subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "validate_sdr.py")],
                   cwd=BASE, env=dict(os.environ, SDR_REPORTS_DIR=tmp_reports),
                   capture_output=True, text=True, timeout=600)
    fresh_results = os.path.join(tmp_reports, "ksi-test-results.json")
    check("validator wrote ksi-test-results.json", os.path.exists(fresh_results))
    if not os.path.exists(fresh_results):
        print(f"\nFAIL: assurance graph method count ({_fail} failures)")
        return 1

    graph = _load(GRAPH)
    coverage = _load(COVERAGE)
    ksi_results = _load(fresh_results)

    ksi_nodes = [n for n in graph.get("nodes", []) if n.get("node_kind") == "ksi"]

    # 3. Every KSI node exposes the explicit automated-method fields (not just a
    #    raw methods list) so a reviewer can see the real count.
    have_fields = all(
        "automated_methods" in n.get("verification", {})
        and "unclassified_string_tests" in n.get("verification", {})
        for n in ksi_nodes)
    check("every KSI node carries automated_methods + unclassified_string_tests",
          have_fields)

    # 4. Cross-report parity: the coverage report's
    #    ksis_meeting_verification_minimum must equal the number of KSI results
    #    the authoritative validator marks meets_test_minimum == True.
    # The validator writes its per-KSI list under "results". This test once
    # read a key that did not exist ("ksi_results"), so validator_met was
    # always 0 and the parity check passed 0 == 0 while nothing met the
    # minimum (RULE 7: an empty-vs-empty reconciliation is a false pass). Read
    # the real key and refuse an empty result set.
    results = ksi_results.get("results") or []
    check(f"validator report carries a non-empty per-KSI result list (keys={sorted(ksi_results)})",
          len(results) > 0)
    validator_met = sum(
        1 for r in results
        if r.get("meets_test_minimum") is True)
    graph_met = sum(
        1 for n in ksi_nodes
        if n.get("verification", {}).get("meets_minimum") is True)
    reported = coverage.get("ksis_meeting_verification_minimum")
    check("coverage ksis_meeting_verification_minimum == validator meets count "
          f"(coverage={reported}, validator={validator_met})",
          reported == validator_met)
    check(f"graph meets_minimum count == validator meets count "
          f"(graph={graph_met}, validator={validator_met})",
          graph_met == validator_met)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: assurance graph method count "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
