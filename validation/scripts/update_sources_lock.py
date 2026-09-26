#!/usr/bin/env python3
"""Update sources.lock.json from the pinned files CURRENTLY on disk.

Used by the drift-adopt workflow and by any manual adoption of an upstream
change: after a new upstream file is copied into its pinned path, the file and
the old lock hash disagree, and validate_upstream / sources_lock_consistency
(correctly) hard-fail on that mismatch. This regenerates the lock from the files
on disk so the update becomes a coherent, reviewable PR. It does NOT disable the
lock check - it produces the new lock as part of the change. Never hand-edit a
hash; run this instead, and commit the result with the pinned file.

What is refreshed:

  * cr26_consolidated_rules: version (dataset info.version) and sha256, plus
    --upstream-commit provenance when given.
  * cr26_rules_schema: sha256 (and --upstream-commit).
  * Every other entry with a pinned_path: sha256 recomputed from disk, and when
    the pinned file is a JSON schema carrying "$schemaVersion", schema_version
    is set to it (FedRAMP edits schema files in place without renaming, so the
    version inside the file is the only reliable signal).
  * verified_current_on: only when --verified-on is given. That field claims
    the pins were checked against upstream on that date, which this offline
    script cannot know; the caller (the drift workflow, or a human who just
    diffed against upstream) asserts it explicitly.

    python validation/scripts/update_sources_lock.py [--upstream-commit SHA]
                                                      [--verified-on YYYY-MM-DD]
"""

import argparse
import collections
import datetime
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


def _schema_version(path):
    """Return the file's $schemaVersion, or None if it is not a JSON schema."""
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read().decode("utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    return doc.get("$schemaVersion")


def refresh_lock(lock, upstream_commit=None, verified_on=None):
    """Refresh every pinned entry in `lock` in place; return a change summary."""
    changes = []
    sources = lock["sources"]

    ds = json.load(open(DATASET, encoding="utf-8"))
    version = ds.get("info", {}).get("version")
    entry = sources["cr26_consolidated_rules"]
    if entry.get("version") != version:
        changes.append(f"cr26_consolidated_rules version {entry.get('version')} -> {version}")
    entry["version"] = version
    digest = _sha256(DATASET)
    if entry.get("sha256") != digest:
        changes.append(f"cr26_consolidated_rules sha256 -> {digest[:12]}")
    entry["sha256"] = digest
    if upstream_commit:
        entry["upstream_commit"] = upstream_commit

    # Also refresh the rules-schema lock entry so a dataset+schema adoption is
    # atomic and validate_upstream's schema-hash check passes on the new pair.
    schema_path = os.path.join(BASE, "references", "fedramp-consolidated-rules.schema.json")
    if os.path.isfile(schema_path) and "cr26_rules_schema" in sources:
        sc = sources["cr26_rules_schema"]
        sc_digest = _sha256(schema_path)
        if sc.get("sha256") != sc_digest:
            changes.append(f"cr26_rules_schema sha256 -> {sc_digest[:12]}")
        sc["sha256"] = sc_digest
        if upstream_commit:
            sc["upstream_commit"] = upstream_commit

    # Every other pinned entry: hash from disk, schema_version from the file.
    for key, ent in sources.items():
        if key in ("cr26_consolidated_rules", "cr26_rules_schema"):
            continue
        rel = ent.get("pinned_path")
        if not rel:
            continue
        path = os.path.join(BASE, rel)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{key}: pinned_path {rel} is missing on disk")
        digest = _sha256(path)
        if ent.get("sha256") != digest:
            changes.append(f"{key} sha256 -> {digest[:12]}")
        ent["sha256"] = digest
        sv = _schema_version(path)
        if sv is not None and "schema_version" in ent and ent["schema_version"] != sv:
            changes.append(f"{key} schema_version {ent['schema_version']} -> {sv}")
            ent["schema_version"] = sv

    if verified_on:
        datetime.date.fromisoformat(verified_on)  # reject a malformed date
        if lock.get("verified_current_on") != verified_on:
            changes.append(f"verified_current_on -> {verified_on}")
        lock["verified_current_on"] = verified_on
    return changes


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream-commit")
    ap.add_argument("--verified-on", metavar="YYYY-MM-DD",
                    help="date the pins were verified current against upstream")
    args = ap.parse_args(argv)

    lock = json.load(open(LOCK, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    changes = refresh_lock(lock, args.upstream_commit, args.verified_on)
    with open(LOCK, "w", encoding="utf-8", newline="\n") as f:
        json.dump(lock, f, indent=1)
    if changes:
        print("sources.lock updated:")
        for c in changes:
            print(f"  {c}")
    else:
        print("sources.lock already matches every pinned file on disk (no change)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
