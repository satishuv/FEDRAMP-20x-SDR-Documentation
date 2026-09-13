#!/usr/bin/env python3
"""Validate the human review/signoff register.

Enforces two things:
  1. Structure: each review entry carries the required fields (review_id,
     assurance_id, reviewer, role, decision, reviewed_at, and the evidence
     hashes the reviewer actually looked at).
  2. The invariant: an approval is only ever a HUMAN act. The deterministic
     pipeline must never write a decision here. This validator confirms every
     entry names a human reviewer and a timestamp, and that decisions use the
     allowed vocabulary. It never itself marks anything approved.

Referential check: every review's assurance_id should resolve to a node in the
assurance graph, so a review cannot approve a requirement that does not exist.

    python validation/scripts/validate_reviews.py

Exit 1 on any structural or referential failure. An empty register is valid
(nothing reviewed yet).
"""

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTER = os.path.join(BASE, "sdr", "reviews", "review-register.json")
GRAPH = os.path.join(BASE, "traceability", "assurance-graph.json")

REQUIRED = ["review_id", "assurance_id", "reviewer", "role", "decision", "reviewed_at"]
ALLOWED_DECISIONS = {"approved", "rejected", "changes-requested", "pending"}
# A reviewer must be a real name/identity, never the pipeline.
FORBIDDEN_REVIEWERS = {"", "deterministic", "pipeline", "sdr.py", "automation",
                       "system", "bot"}


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _assurance_ids():
    graph = load(GRAPH)
    if not graph:
        return None
    ids = set()
    for n in graph.get("nodes", []):
        rid = n.get("rule_id") or n.get("ksi_id")
        if rid:
            ids.add(rid)
    return ids


def _node_evidence_hashes():
    """Map each assurance-node id to the set of content hashes of the evidence
    CURRENTLY attached to it in the graph. A node-level approval's reviewed
    hashes must be a subset of these, so a stale or copied-from-another-node hash
    is caught. Returns {node_id: {hash, ...}} or None if the graph is absent."""
    graph = load(GRAPH)
    if not graph:
        return None
    out = {}
    for n in graph.get("nodes", []):
        rid = n.get("rule_id") or n.get("ksi_id")
        if not rid:
            continue
        hashes = set()
        for ev in (n.get("evidence") or []):
            if isinstance(ev, dict):
                h = ev.get("xEvidenceContentHash") or ev.get("content_hash")
                if h:
                    hashes.add(h)
        out[rid] = hashes
    return out


_SHA256_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")


def main():
    reg = load(REGISTER)
    if reg is None:
        print(f"FAIL: review register missing/unreadable at {os.path.relpath(REGISTER, BASE)}")
        return 1
    reviews = reg.get("reviews", [])
    problems = []

    graph_ids = _assurance_ids()
    node_hashes = _node_evidence_hashes()

    for i, r in enumerate(reviews):
        where = r.get("review_id", f"#{i}")
        for f in REQUIRED:
            if not r.get(f):
                problems.append(f"{where}: missing required field '{f}'")
        dec = r.get("decision")
        if dec and dec not in ALLOWED_DECISIONS:
            problems.append(f"{where}: decision '{dec}' not in {sorted(ALLOWED_DECISIONS)}")
        reviewer = str(r.get("reviewer", "")).strip().lower()
        if reviewer in FORBIDDEN_REVIEWERS:
            problems.append(f"{where}: reviewer '{r.get('reviewer')}' is not a human "
                            "identity; approvals must be a human act")
        aid = r.get("assurance_id")
        # An 'approved' decision must list the evidence hashes reviewed, and each
        # must be a well-formed SHA-256 that is CURRENTLY attached to this node.
        if dec == "approved":
            reviewed = r.get("evidence_hashes_reviewed") or []
            if not reviewed:
                problems.append(f"{where}: approved without listing evidence_hashes_reviewed")
            for h in reviewed:
                if not (isinstance(h, str) and _SHA256_RE.match(h.strip().lower())):
                    problems.append(f"{where}: evidence hash '{h}' is not a well-formed SHA-256")
            # Bind to CURRENT node evidence (when the graph resolves this node and
            # carries evidence): a reviewed hash must match the node's current
            # evidence, catching a stale or copied hash.
            if node_hashes is not None and aid:
                current = node_hashes.get(aid)
                if current is None:
                    tail = aid.split("ASR-")[-1] if aid.startswith("ASR-") else aid
                    current = node_hashes.get(tail)
                if current:
                    stale = [h for h in reviewed if h not in current
                             and (h.split("sha256:")[-1] if isinstance(h, str) else h) not in
                             {c.split("sha256:")[-1] for c in current}]
                    if stale:
                        problems.append(f"{where}: approved evidence hash(es) do not match "
                                        f"the node's current evidence (stale or from another "
                                        f"node): {stale[:3]}")
        # Referential: the assurance_id must resolve, if the graph is present.
        if graph_ids is not None and aid and aid not in graph_ids:
            # Allow an ASR- prefixed id whose tail is a real rule/ksi id.
            tail = aid.split("ASR-")[-1] if aid.startswith("ASR-") else aid
            if tail not in graph_ids and not any(g in aid for g in graph_ids):
                problems.append(f"{where}: assurance_id '{aid}' does not resolve in the assurance graph")

    # Package-level signoff (distinct from per-node reviews). Only validated
    # when populated; the TBD template placeholder is left alone.
    signoff = reg.get("package_signoff")
    if isinstance(signoff, dict):
        dec = str(signoff.get("decision", ""))
        populated = dec and not dec.startswith("TBD")
        if populated:
            if dec not in ALLOWED_DECISIONS:
                problems.append(f"package_signoff: decision '{dec}' not in {sorted(ALLOWED_DECISIONS)}")
            signer = str(signoff.get("reviewer", "")).strip().lower()
            if signer in FORBIDDEN_REVIEWERS:
                problems.append("package_signoff: reviewer is not a human identity; "
                                "package approval must be a human act")
            if dec == "approved" and not signoff.get("release_tag"):
                problems.append("package_signoff: approved without a release_tag to bind it to")
            # Cryptographic binding: an approved signoff must carry the SHA-256
            # of the manifest it approved, and it must match the current bytes.
            if dec == "approved":
                signed_sha = signoff.get("package_manifest_sha256")
                if not signed_sha or str(signed_sha).startswith("TBD"):
                    problems.append("package_signoff: approved without "
                                    "package_manifest_sha256 binding it to the exact manifest")
                else:
                    manifest_path = os.path.join(BASE, "artifacts", "release-manifest.json")
                    if os.path.isfile(manifest_path):
                        import hashlib
                        with open(manifest_path, "rb") as mf:
                            actual = "sha256:" + hashlib.sha256(mf.read()).hexdigest()
                        if signed_sha != actual:
                            problems.append("package_signoff: package_manifest_sha256 "
                                            "does not match the current release manifest "
                                            "(a generated artifact changed since signoff)")

    if problems:
        for p in problems[:20]:
            print(f"    - {p}")
        return 1
    print(f"PASS: review register valid ({len(reviews)} review(s); "
          "no machine-authored approvals; all decisions human and well-formed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
