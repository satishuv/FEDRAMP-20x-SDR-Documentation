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

try:
    from sign_evidence import verify_signature_offline as _sig_verify
except Exception:
    _sig_verify = None

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")


def load_trusted_signer():
    """Load the INDEPENDENTLY PINNED evidence signer from the offering profile
    (findings 7/8). Returns {"public_key": <PEM str>, "key_arn": <arn or None>,
    "public_key_fingerprint": <'sha256:..' or None>} or None when no signer is
    pinned. The public key is pinned by the VERIFIER (obtained once via
    kms:GetPublicKey), NOT taken from the evidence. A public_key_pem_path is
    resolved relative to the repo so the key can live in a file. A TBD/empty
    value is treated as 'not pinned'."""
    prof = load(PROFILE, {}) or {}
    signer = prof.get("expected_evidence_signer") or {}
    if not isinstance(signer, dict):
        return None
    pem = signer.get("public_key_pem")
    pem_path = signer.get("public_key_pem_path")
    if (not pem or str(pem).startswith("TBD")) and pem_path and not str(pem_path).startswith("TBD"):
        cand = pem_path if os.path.isabs(pem_path) else os.path.join(BASE, pem_path)
        if os.path.isfile(cand):
            try:
                with open(cand, encoding="utf-8") as f:
                    pem = f.read()
            except OSError:
                pem = None
    if not pem or str(pem).startswith("TBD"):
        return None
    arn = signer.get("key_arn")
    fp = signer.get("public_key_fingerprint")
    return {
        "public_key": pem,
        "key_arn": None if (not arn or str(arn).startswith("TBD")) else arn,
        "public_key_fingerprint": None if (not fp or str(fp).startswith("TBD")) else fp,
    }


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


def classify_entry(e, hash_fn=None, trusted_signer=None):
    """Pure integrity decision for one evidence entry. Returns
    (outcome, message) where outcome is 'verified' | 'finding' | 'hard'.
    hash_fn is the canonical evidence hash implementation (or None if it could
    not be imported). Keeping this pure makes the fail-closed contract testable
    without disk I/O; main() calls it for every entry."""
    loc = e.get("evidenceLocation", "") or e.get("artifact_uri", "")
    h = e.get("xEvidenceContentHash") or e.get("stored_sha256")
    if not h:
        return ("finding", "no content hash yet")
    if not HASH_RE.match(str(h)):
        return ("hard", f"malformed content hash {h!r} (expected 'sha256:<64 hex>')")
    if isinstance(loc, str) and loc.startswith("sdr://placeholder/"):
        return ("finding", "placeholder location (not yet real)")
    source, kind = _resolve_source(e)
    if source is None:
        return ("finding", f"integrity unverifiable ({kind}) - stored hash is "
                           "well-formed but no source to recompute")
    if hash_fn is None:
        # Fail CLOSED: the validator claims real cryptographic verification, so
        # losing the canonical hash implementation means it CANNOT verify
        # integrity - a hard failure, not a soft "unverifiable" finding.
        # Inability to perform an integrity check is not successful validation.
        return ("hard", "INTEGRITY UNVERIFIABLE - the canonical evidence hash "
                        "implementation (evidence_wiring.evidence_hash) could not "
                        "be imported; refusing to pass evidence integrity without "
                        "the ability to recompute the digest")
    if hash_fn(source) != h:
        return ("hard", f"INTEGRITY FAILED - stored {str(h)[:20]} != recomputed "
                        f"{hash_fn(source)[:20]} (content changed after the digest "
                        "was recorded)")
    # Non-repudiation verification (AU-09(02/03/04), AU-10). Signing is opt-in
    # per deployment, so an ABSENT signature leaves the entry verified-by-hash.
    # A PRESENT signature is CRYPTOGRAPHICALLY VERIFIED against an INDEPENDENTLY
    # PINNED trusted signer (findings 7 and 8): the gate never trusts the keyId
    # carried inside the evidence, and never treats a mere well-formed blob as
    # verified. It checks (a) the evidence's keyId matches the pinned trusted
    # key ARN, (b) the signedHash binds to THIS content, and (c) the signature
    # verifies offline under the pinned public key. Any failure is HARD
    # (fail-closed): a present-but-unverifiable signature is worse than none.
    sig = e.get("xEvidenceSignature")
    if sig is not None:
        if not isinstance(sig, dict):
            return ("hard", "xEvidenceSignature present but not an object")
        signed_hash = sig.get("signedHash")
        if not sig.get("signature") or not sig.get("keyId") or not signed_hash:
            return ("hard", "xEvidenceSignature present but missing "
                            "signature/keyId/signedHash")
        if signed_hash != h:
            return ("hard", f"SIGNATURE BINDING STALE - signed {str(signed_hash)[:20]} "
                            f"!= current {str(h)[:20]} (evidence changed after it "
                            "was signed; the signature is over old content)")
        # A signature is present, so a trusted signer MUST be pinned and it MUST
        # verify. Without a pinned signer we cannot assert non-repudiation, and
        # trusting the evidence's own keyId would be circular - fail closed.
        if not trusted_signer or not trusted_signer.get("public_key"):
            return ("hard", "xEvidenceSignature present but no trusted signer is "
                            "pinned (offering-profile.expected_evidence_signer with "
                            "a public_key_pem); refusing to trust a signature whose "
                            "signer is not independently pinned (findings 7/8)")
        pinned_arn = trusted_signer.get("key_arn")
        if pinned_arn and sig.get("keyId") != pinned_arn:
            return ("hard", f"SIGNER NOT TRUSTED - evidence keyId {str(sig.get('keyId'))[:40]} "
                            f"is not the pinned trusted signer {str(pinned_arn)[:40]} "
                            "(a signature by an unpinned key is not trusted)")
        if _sig_verify is None:
            return ("hard", "cannot verify evidence signature - the offline "
                            "verifier (sign_evidence.verify_signature_offline) "
                            "could not be imported; refusing to pass a signed "
                            "entry without verifying it")
        try:
            ok = _sig_verify(sig, trusted_signer["public_key"],
                             recomputed_hash=h,
                             expected_fingerprint=trusted_signer.get("public_key_fingerprint"))
        except Exception as ex:  # noqa: BLE001 - structural verify error
            return ("hard", f"SIGNATURE VERIFICATION ERROR - {ex}")
        if not ok:
            return ("hard", "SIGNATURE INVALID - the signature does not verify "
                            "under the pinned trusted signer public key "
                            "(cryptographic verification failed, fail-closed)")
    return ("verified", "")


def main():
    records = load(RECORDS, {"frr": {}, "ksi": {}})
    trusted_signer = load_trusted_signer()
    hard, findings = [], []
    checked = verified = 0

    for oid, section, e in iter_evidence(records):
        checked += 1
        outcome, msg = classify_entry(e, _evidence_hash, trusted_signer)
        if outcome == "hard":
            hard.append(f"{section}:{oid}: {msg}")
        elif outcome == "finding":
            findings.append(f"{section}:{oid}: {msg}")
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
