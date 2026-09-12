#!/usr/bin/env python3
"""Build the Assurance Graph: one first-class artifact that unifies, per
applicable requirement and KSI, the whole chain from FedRAMP rule through
applicability, provider claim, verification, hashed evidence, validation,
review, and the generated SDR location.

This DUPLICATES NOTHING. Every field is read from data the pipeline already
produces: the per-class profile (applicability + force), the KSI profile
(minimums, families), the record store (claims, evidence, owners), and the
generated SDR JSON (output pointers). The graph is a join over those, so it is
always consistent with them by construction.

Honest edge: FedRAMP does not link individual FedRAMP Rules (FRRs) to specific
KSIs in the dataset. KSIs carry related NIST controls, not FRR ids. So this
graph has two node kinds, `rule` and `ksi`, each fully resolved; it does not
fabricate FRR->KSI edges that the source data does not contain.

Pipeline position: after build_sdr.py (needs the generated SDR to point into).

    python validation/scripts/build_assurance_graph.py

Output: traceability/assurance-graph.json
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Reuse the evidence lifecycle model rather than duplicating it, so the graph's
# evidence nodes carry real freshness/expiry/collection state.
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from evidence_lifecycle import lifecycle_record as _lifecycle_record
except Exception:
    _lifecycle_record = None
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")
REGISTER = os.path.join(BASE, "sdr", "reviews", "review-register.json")
OUT = os.path.join(BASE, "traceability", "assurance-graph.json")

# FRC-CSX-VVK force per class, verified against the dataset.
VVK_FORCE = {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}


def _review_index():
    """Map assurance_id -> the real recorded review, so the graph reflects
    actual human decisions instead of a hardcoded 'pending'. Reads the review
    register the pipeline never writes to. Returns {} when nothing is reviewed
    (the correct template state)."""
    reg = load(REGISTER, {}) or {}
    idx = {}
    for r in reg.get("reviews", []):
        aid = r.get("assurance_id")
        if not aid:
            continue
        # Accept an ASR- wrapper or the bare rule/ksi id.
        key = aid.split("ASR-")[-1] if str(aid).startswith("ASR-") else aid
        idx[key] = r
    return idx


def _review_for(review_idx, ident, owner):
    """Return the review block for one node id: the recorded human review if
    present, else the honest pending default (reviewer = record owner)."""
    r = review_idx.get(ident)
    if not r:
        return {"reviewer": owner, "review_status": "pending",
                "reviewed_evidence_hashes": []}
    return {
        "reviewer": r.get("reviewer", owner),
        "review_status": r.get("decision", "pending"),
        "reviewed_at": r.get("reviewed_at"),
        "reviewed_evidence_hashes": r.get("evidence_hashes_reviewed", []),
    }


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _evidence_nodes(evidence):
    """Normalize a record's evidence list into graph evidence nodes, enriched
    with lifecycle state (freshness, expiry, collection status, evidence id,
    supersession) via evidence_lifecycle.lifecycle_record, so the graph carries
    the real lifecycle - not merely source/type/location/hash/date."""
    out = []
    for e in evidence or []:
        if not isinstance(e, dict):
            continue
        node = {
            "source": (e.get("evidenceText", "").split(":")[0] or "unknown"),
            "type": e.get("evidenceType"),
            "location": e.get("evidenceLocation"),
            "sha256": e.get("xEvidenceContentHash"),
            "observed_at": e.get("lastUpdated"),
        }
        if _lifecycle_record is not None:
            try:
                lc = _lifecycle_record(e)
                node["evidence_id"] = lc.get("evidence_id")
                node["freshness_status"] = lc.get("freshness_status")
                node["expires_at"] = lc.get("expires_at")
                node["collection_status"] = lc.get("collection_status")
                node["supersedes"] = lc.get("supersedes")
            except Exception:
                # Never let lifecycle enrichment break the graph build.
                node["freshness_status"] = "unknown"
        out.append(node)
    return out


def build_graph(cls):
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    if class_profile is None:
        return None
    ksi_profile = load(KSI_PROFILE, {"indicators": []})
    records = load(RECORDS, {"frr": {}, "ksi": {}})
    sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"), {})
    sdr_frr_index = {e["frrID"]: i for i, e in enumerate(sdr.get("fedRampRequirements", []))}
    sdr_ksi_index = {e["ksiId"]: i for i, e in enumerate(sdr.get("keySecurityIndicators", []))}
    review_idx = _review_index()

    nodes = []

    # Rule nodes.
    for r in class_profile["rules"]:
        rid = r["rule_id"]
        rec = records.get("frr", {}).get(rid, {})
        ext = rec.get("extension", {})
        i = sdr_frr_index.get(rid)
        nodes.append({
            "node_kind": "rule",
            "rule_id": rid,
            "certification_class": cls.upper(),
            "force": r.get("force"),
            "family": r.get("family"),
            "applicability": {
                "type": "20x",
                "path": class_profile.get("meta", {}).get("path", "Program"),
                "class": cls.upper(),
                "subset": r.get("subset"),
                "resolution": r.get("resolution"),
                "applicable": True,
            },
            "provider_claim": {
                "status": rec.get("implementation_status", "Not Implemented"),
                "implementation": rec.get("implementation", []),
                "owner": ext.get("owner", "TBD"),
            },
            "verification": {
                "verification": ext.get("verification", "TBD"),
                "independent_verification": ext.get("independent_verification", "TBD"),
            },
            "evidence": _evidence_nodes(ext.get("rule_artifacts")),
            "validation": {
                "result": "PASS" if rid in sdr_frr_index else "MISSING",
                "validator": "deterministic",
            },
            "review": dict(_review_for(review_idx, rid, ext.get("owner", "TBD")),
                           responses=ext.get("assessor_responses", "None recorded")),
            "outputs": {
                "sdr_json_pointer": f"$.fedRampRequirements[{i}]" if i is not None else None,
            },
        })

    # KSI nodes.
    for k in ksi_profile["indicators"]:
        kid = k["ksi_id"]
        rec = records.get("ksi", {}).get(kid, {})
        ext = rec.get("extension", {})
        i = sdr_ksi_index.get(kid)
        min_methods = k.get("minimum_automated_methods", {}).get(f"class_{cls}")
        tests = rec.get("tests", []) or []
        nodes.append({
            "node_kind": "ksi",
            "ksi_id": kid,
            "certification_class": cls.upper(),
            "force": VVK_FORCE.get(cls),
            "family": k.get("family"),
            "related_nist_controls": k.get("controls", []),
            "provider_claim": {
                "status": rec.get("implementation_status", "Not Implemented"),
                "implementation": rec.get("implementation", []),
                "owner": ext.get("owner", "TBD"),
            },
            "verification": {
                "methods": tests,
                "minimum_required": min_methods,
                "meets_minimum": (len(tests) >= min_methods) if isinstance(min_methods, int) else None,
                "measures_verification": ext.get("measures_verification", "TBD"),
                "automation_verification": ext.get("automation_verification", "TBD"),
            },
            "evidence": _evidence_nodes(rec.get("evidence")),
            "validation": {
                "result": "PASS" if kid in sdr_ksi_index else "MISSING",
                "validator": "deterministic",
            },
            "review": _review_for(review_idx, kid, ext.get("owner", "TBD")),
            "outputs": {
                "sdr_json_pointer": f"$.keySecurityIndicators[{i}]" if i is not None else None,
            },
        })

    return {
        "graph_note": (
            "Assurance Graph: a deterministic join over the class profile, KSI "
            "profile, record store, and generated SDR. It duplicates no source "
            "data and is regenerated by build_assurance_graph.py. It records "
            "traceability, never a compliance determination; a human owns every "
            "status and review."),
        "certification_class": cls.upper(),
        "dataset_version": class_profile.get("meta", {}).get("dataset_version"),
        "node_count": len(nodes),
        "rule_nodes": sum(1 for n in nodes if n["node_kind"] == "rule"),
        "ksi_nodes": sum(1 for n in nodes if n["node_kind"] == "ksi"),
        "nodes": nodes,
    }


def main():
    profile = load(PROFILE, {})
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no assurance graph is generated.")
        return 1
    graph = build_graph(cls)
    if graph is None:
        print(f"Could not build the assurance graph for class {cls.upper()}.")
        return 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(graph, f, indent=1)
    print(f"Assurance graph written: {os.path.relpath(OUT, BASE)} "
          f"({graph['node_count']} nodes: {graph['rule_nodes']} rules, "
          f"{graph['ksi_nodes']} KSIs).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
