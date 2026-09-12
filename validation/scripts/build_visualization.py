#!/usr/bin/env python3
"""Render the assurance graph as a single self-contained HTML view.

A reviewer opens artifacts/assurance-graph.html in a browser and sees every
rule and KSI, its evidence count, validation result, and review status, with
filtering. No external dependencies, no network, no build tools: the graph JSON
is embedded and the page renders itself with vanilla JS. Deterministic (no run
timestamps) so it is reproducible.

    python validation/scripts/build_visualization.py

Output: artifacts/assurance-graph.html
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GRAPH = os.path.join(BASE, "traceability", "assurance-graph.json")
OUT = os.path.join(BASE, "artifacts", "assurance-graph.html")

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assurance graph &mdash; Class {cls}</title>
<style>
 body{{font:14px system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 header{{padding:16px 20px;background:#161a22;border-bottom:1px solid #2a2f3a}}
 h1{{font-size:18px;margin:0 0 4px}} .sub{{color:#9aa4b2;font-size:12px}}
 .bar{{padding:10px 20px;background:#12151c;border-bottom:1px solid #2a2f3a}}
 .bar input,.bar select{{background:#0f1115;color:#e6e6e6;border:1px solid #2a2f3a;padding:6px 8px;border-radius:6px}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{text-align:left;padding:8px 20px;border-bottom:1px solid #21262f;font-size:13px}}
 th{{color:#9aa4b2;position:sticky;top:0;background:#12151c;cursor:pointer}}
 .kind{{font-size:11px;padding:2px 6px;border-radius:4px;background:#243b53}}
 .kind.ksi{{background:#3b2d53}}
 .pass{{color:#6ee7a0}} .fail{{color:#f08a8a}} .pend{{color:#e6c86e}}
 .note{{padding:14px 20px;color:#9aa4b2;font-size:12px}}
</style></head><body>
<header>
 <h1>Assurance graph &mdash; Class {cls}</h1>
 <div class="sub">Dataset {dataset} &middot; {count} nodes ({rules} rules, {ksis} KSIs).
 A traceability view, not a compliance determination. Nothing here is approved,
 assessed, or certified by the tool.</div>
</header>
<div class="bar">
 <input id="q" placeholder="filter by id or text&hellip;" oninput="render()">
 <select id="kind" onchange="render()">
  <option value="">all kinds</option><option value="rule">rules</option><option value="ksi">KSIs</option>
 </select>
 <select id="val" onchange="render()">
  <option value="">all validation</option><option value="PASS">PASS</option><option value="FAIL">FAIL</option>
 </select>
</div>
<table><thead><tr>
 <th onclick="sortBy('id')">ID</th><th>Kind</th><th>Evidence</th>
 <th>Validation</th><th>Review</th><th>Summary</th>
</tr></thead><tbody id="rows"></tbody></table>
<div class="note">Generated from traceability/assurance-graph.json. Regenerate
 with <code>python sdr.py build</code>.</div>
<script>
const DATA = {data};
let sortKey = 'id';
function sortBy(k){{sortKey=k;render();}}
function render(){{
 const q=document.getElementById('q').value.toLowerCase();
 const kind=document.getElementById('kind').value;
 const val=document.getElementById('val').value;
 let rows=DATA.nodes.filter(n=>{{
  const id=(n.rule_id||n.ksi_id||'');
  const text=JSON.stringify(n).toLowerCase();
  if(q && !text.includes(q)) return false;
  if(kind && n.node_kind!==kind) return false;
  if(val && (n.validation||{{}}).result!==val) return false;
  return true;
 }});
 rows.sort((a,b)=>((a.rule_id||a.ksi_id||'')>(b.rule_id||b.ksi_id||'')?1:-1));
 const tb=document.getElementById('rows');
 tb.innerHTML=rows.map(n=>{{
  const id=n.rule_id||n.ksi_id||'?';
  const ev=(n.evidence||[]).length;
  const v=(n.validation||{{}}).result||'-';
  const vc=v==='PASS'?'pass':v==='FAIL'?'fail':'pend';
  const rv=(n.review||{{}}).review_status||'pending';
  const sum=(n.statement||n.summary||'').slice(0,90);
  return `<tr><td><b>${{id}}</b></td>
   <td><span class="kind ${{n.node_kind}}">${{n.node_kind}}</span></td>
   <td>${{ev}}</td><td class="${{vc}}">${{v}}</td>
   <td class="pend">${{rv}}</td><td>${{sum}}</td></tr>`;
 }}).join('');
}}
render();
</script></body></html>
"""


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def main():
    graph = load(GRAPH)
    if graph is None:
        print("Assurance graph not found; run build_assurance_graph.py first.")
        return 1
    nodes = graph.get("nodes", [])
    rules = sum(1 for n in nodes if n.get("node_kind") == "rule")
    ksis = sum(1 for n in nodes if n.get("node_kind") == "ksi")
    html = PAGE.format(
        cls=graph.get("certification_class", "?"),
        dataset=graph.get("dataset_version", "?"),
        count=len(nodes), rules=rules, ksis=ksis,
        data=json.dumps(graph, separators=(",", ":"), sort_keys=True),
    )
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print(f"Visualization written: {os.path.relpath(OUT, BASE)} "
          f"({len(nodes)} nodes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
