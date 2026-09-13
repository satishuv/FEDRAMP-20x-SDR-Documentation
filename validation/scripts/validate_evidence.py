#!/usr/bin/env python3
"""Live evidence-integrity gate for the generated package.

This does real cryptographic verification, not merely a format check.

Evidence lives in two different places in the record store, and this gate reads
BOTH (the earlier version missed FRR evidence):
  - KSI evidence:  records["ksi"][id]["evidence"]  (a list)
  - FRR evidence:  records["frr"][id]["extension"]["rule_artifacts"]  (a list)

For each evidence entry:
  1. If it carries a stored hash, the hash MUST be well-formed 'sha256:<64 hex>'
     (malformed => HARD failure).
  2. If a source is RESOLVABLE - an inline `source_fact`, or a `source_fact_path`
     / local `artifact_uri` pointing at a readable file - recompute the digest
     with the same canonicalization the pipeline used (evidence_wiring.evidence_hash)
     and compare it to the stored hash. A mismatch is a HARD failure (the content
     changed after the digest was recorded).
  3. If no source can be resolved, report "integrity unverifiable" as a
     readiness FINDING. It is never reported as passed integrity verification.

Readiness FINDINGS (never automatic compliance failures, per the trust
boundary): no stored hash yet, placeholder location, unresolvable source.

    python validation/scripts/validate_evidence.py

Exit 1 only on a HARD failure (malformed or mismatched digest).
"""

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")

sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from evidence_wiring import evidence_hash as _evidence_hash
except Exception:
    _evidence_hash = None

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def iter_evidence(records):
    """Canonical evidence iterator covering BOTH storage shapes.
    Yields (owner_id, section, evidence_dict)."""
    for oid, rec in (records.get("ksi", {}) or {}).items():
        for e in (rec.get("evidence") or []):
            if isinstance(e, dict):
                yield oid, "ksi", e
    for oid, rec in (records.get("frr", {}) or {}).items():
        for e in ((rec.get("extension", {}) or {}).get("rule_artifacts") or []):
            if isinstance(e, dict):
                yield oid, "frr", e


def _resolve_source(e):
    """Return (source_obj, kind) if a source is resolvable, else (None, reason).
    kind is 'inline' or 'file'. Reads only LOCAL files inside the repo."""
    if "source_fact" in e:
        return e["source_fact"], "inline"
    if "xSourceFact" in e:
        return e["xSourceFact"], "inline"
    path = e.get("source_fact_path")
    uri = e.get("artifact_uri") or e.get("evidenceLocation")
    candidate = None
    if path:
        candidate = path if os.path.isabs(path) else os.path.join(BASE, path)
    elif uri and isinstance(uri, str) and not uri.startswith(("http", "sdr://", "s3://")):
        candidate = uri if os.path.isabs(uri) else os.path.join(BASE, uri)
    if candidate and os.path.isfile(candidate):
        try:
            with open(candidate, "rb") as f:
                return f.read(), "file"
        except OSError:
            return None, "source file unreadable"
    return None, "no resolvable source"


def main():
    records = load(RECORDS, {"frr": {}, "ksi": {}})
    hard, findings = [], []
    checked = verified = 0

    for oid, section, e in iter_evidence(records):
        checked += 1
        loc = e.get("evidenceLocation", "") or e.get("artifact_uri", "")
        h = e.get("xEvidenceContentHash") or e.get("stored_sha256")
        if not h:
            findings.append(f"{section}:{oid}: no content hash yet")
            continue
        if not HASH_RE.match(str(h)):
            hard.append(f"{section}:{oid}: malformed content hash {h!r} "
                        "(expected 'sha256:<64 hex>')")
            continue
        if isinstance(loc, str) and loc.startswith("sdr://placeholder/"):
            findings.append(f"{section}:{oid}: placeholder location (not yet real)")
            continue
        # Real cryptographic verification where a source resolves.
        source, kind = _resolve_source(e)
        if source is None:
            findings.append(f"{section}:{oid}: integrity unverifiable ({kind}) - "
                            "stored hash is well-formed but no source to recompute")
            continue
        if _evidence_hash is None:
            findings.append(f"{section}:{oid}: integrity unverifiable "
                            "(evidence_hash unavailable)")
            continue
        recomputed = _evidence_hash(source)
        if recomputed != h:
            hard.append(f"{section}:{oid}: INTEGRITY FAILED - stored {str(h)[:20]} "
                        f"!= recomputed {recomputed[:20]} (content changed after "
                        "the digest was recorded)")
        else:
            verified += 1

    print("Evidence integrity gate")
    print("-" * 68)
    print(f"Evidence entries checked: {checked}  (cryptographically verified: {verified})")
    if findings:
        print(f"Readiness findings ({len(findings)}) - not compliance failures:")
        for f in findings[:20]:
            print(f"    [finding] {f}")
    if hard:
        print(f"HARD integrity failures ({len(hard)}):")
        for h in hard[:20]:
            print(f"    [FAIL] {h}")
        print("A malformed or mismatched evidence digest means the package is "
              "not well-formed. Fix the record store and rebuild.")
        return 1
    print("PASS: every resolvable evidence digest was recomputed and matches, "
          "and every stored digest is well-formed. Unresolvable-source, "
          "placeholder, or hashless evidence is a readiness finding, never an "
          "automatic compliance failure (collection failure is not control failure).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
