#!/usr/bin/env python3
"""Update sources.lock.json for the CURRENTLY pinned dataset file.

Used by the drift-adopt workflow: after downloading a new upstream dataset, the
pinned file and the old lock hash disagree, and validate_upstream (correctly)
hard-fails on that mismatch. This regenerates the lock's dataset hash and version
from the file on disk so the update becomes a coherent, reviewable PR. It does
NOT disable the lock check - it produces the new lock as part of the change.

Optionally accepts --upstream-commit to record provenance.

    python validation/scripts/update_sources_lock.py [--upstream-commit SHA]
"""

import argparse
import collections
import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
LOCK = os.path.join(BASE, "references", "sources.lock.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--upstream-commit")
    args = ap.parse_args(argv)

    ds = json.load(open(DATASET, encoding="utf-8"))
    version = ds.get("info", {}).get("version")
    digest = _sha256(DATASET)

    lock = json.load(open(LOCK, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    entry = lock["sources"]["cr26_consolidated_rules"]
    entry["version"] = version
    entry["sha256"] = digest
    if args.upstream_commit:
        entry["upstream_commit"] = args.upstream_commit
    with open(LOCK, "w", encoding="utf-8", newline="\n") as f:
        json.dump(lock, f, indent=1)
    print(f"sources.lock updated: cr26_consolidated_rules version={version} "
          f"sha256={digest[:16]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
