#!/usr/bin/env python3
"""Validate the pinned upstream FedRAMP dataset BEFORE anything derives from it.

FedRAMP's own consumption guidance: fedramp-consolidated-rules.json is the rule
source of truth, and fedramp-consolidated-rules.schema.json is the source of
truth for its structure - validate the rules file against that schema before
relying on automated analysis. This is the first build step, so the whole
pipeline only ever derives from a dataset that is both hash-locked AND
structurally valid against the official schema.

  1. dataset conforms to references/fedramp-consolidated-rules.schema.json
  2. dataset sha256 matches references/sources.lock.json
  3. rules schema sha256 matches the lock

    python validation/scripts/validate_upstream.py

Exit 1 on any failure. This gate is provenance, not a compliance claim.
"""

import hashlib
import json
import os
import sys

import jsonschema

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
SCHEMA = os.path.join(BASE, "references", "fedramp-consolidated-rules.schema.json")
LOCK = os.path.join(BASE, "references", "sources.lock.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _norm(v):
    """The lock stores bare hex; tolerate an optional 'sha256:' prefix."""
    return str(v or "").split(":")[-1]


def main():
    problems = []
    for p in (DATASET, SCHEMA, LOCK):
        if not os.path.isfile(p):
            print(f"FAIL: missing {os.path.relpath(p, BASE)}")
            return 1

    ds = json.load(open(DATASET, encoding="utf-8"))
    schema = json.load(open(SCHEMA, encoding="utf-8"))
    lock = json.load(open(LOCK, encoding="utf-8")).get("sources", {})

    # 1. Structural validation against the official schema.
    try:
        jsonschema.validate(ds, schema)
        print("PASS: dataset conforms to the official FedRAMP rules schema")
    except jsonschema.ValidationError as e:
        loc = "/".join(str(x) for x in e.absolute_path)
        problems.append(f"dataset does not conform to the rules schema at /{loc}: {e.message[:160]}")

    # 2. Dataset hash matches the lock.
    ds_lock = lock.get("cr26_consolidated_rules", {})
    want = _norm(ds_lock.get("sha256"))
    got = _sha256(DATASET)
    if want and want != got:
        problems.append(f"dataset sha256 {got[:20]} != locked {want[:20]}")
    elif want:
        print("PASS: dataset sha256 matches the source lock")

    # 3. Rules-schema hash matches the lock.
    sc_lock = lock.get("cr26_rules_schema", {})
    sc_want = _norm(sc_lock.get("sha256"))
    sc_got = _sha256(SCHEMA)
    if not sc_want:
        problems.append("cr26_rules_schema not present in sources.lock.json")
    elif sc_want != sc_got:
        problems.append(f"rules schema sha256 {sc_got[:20]} != locked {sc_want[:20]}")
    else:
        print("PASS: rules schema sha256 matches the source lock")

    if problems:
        print(f"FAIL: {len(problems)} upstream-integrity problem(s):")
        for p in problems:
            print(f"    - {p}")
        return 1
    print("Upstream dataset is hash-locked and structurally valid; safe to derive from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
