#!/usr/bin/env python3
"""XSS-regression test for the assurance-graph HTML visualization.

Provider-controlled strings (rule/KSI statements, ids) end up in the generated
HTML. This test injects hostile payloads into a graph and asserts the generated
page does not contain them in an executable form: the embedded JSON must escape
</script>, and provider strings are rendered via DOM textContent at runtime
(never interpolated into innerHTML in the template).

    python validation/scripts/test_visualization_xss.py
"""

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "build_visualization", os.path.join(HERE, "build_visualization.py"))
viz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(viz)

XSS1 = "</script><script>window.__xss=1</script>"
XSS2 = "<img src=x onerror=alert(1)>"


def main():
    graph = {
        "certification_class": "B",
        "dataset_version": "2026.07.14.01",
        "nodes": [
            {"node_kind": "rule", "rule_id": "FRR-X",
             "statement": XSS1,
             "validation": {"result": "PASS"}},
            {"node_kind": "ksi", "ksi_id": XSS2,
             "summary": XSS2,
             "validation": {"result": "FAIL"}},
        ],
    }
    tmp = tempfile.mkdtemp(prefix="viz-")
    out = os.path.join(tmp, "assurance-graph.html")
    viz.GRAPH = os.path.join(tmp, "graph.json")
    viz.OUT = out
    import json
    with open(viz.GRAPH, "w", encoding="utf-8") as f:
        json.dump(graph, f)
    viz.main()
    html = open(out, encoding="utf-8").read()

    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    # The literal </script> payload must NOT appear raw in the output (it is
    # escaped in the embedded JSON), so it cannot terminate the script block.
    check("injected </script> is not present raw in the page",
          "</script><script>window.__xss=1</script>" not in html)
    # The injected script's payload must not be executable anywhere in the page.
    check("injected script payload is neutralized",
          "window.__xss=1</script>" not in html)
    # The template must not interpolate provider strings into innerHTML.
    check("template builds rows via textContent, not innerHTML interpolation",
          "tb.innerHTML=rows.map" not in html and "textContent" in html)

    print(f"\n{passed}/{passed + failed} visualization XSS checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
