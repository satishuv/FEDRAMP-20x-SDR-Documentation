#!/usr/bin/env python3
"""Prove the live evidence-integrity gate actually recomputes digests.

The earlier gate only regex-checked the hash format; these tests confirm the
real behavior: a well-formed but WRONG stored hash over a resolvable source is a
HARD failure, and a matching hash passes. Covers both storage shapes
(KSI evidence and FRR extension.rule_artifacts).

    python validation/scripts/test_evidence_integrity.py
"""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))

import validate_evidence as ve
from evidence_wiring import evidence_hash

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def _count_hard(records):
    """Run the gate's core over an in-memory record store; return hard-fail count."""
    hard = []
    for oid, section, e in ve.iter_evidence(records):
        h = e.get("xEvidenceContentHash") or e.get("stored_sha256")
        if not h:
            continue
        if not ve.HASH_RE.match(str(h)):
            hard.append((section, oid, "malformed"))
            continue
        source, kind = ve._resolve_source(e)
        if source is None:
            continue
        if evidence_hash(source) != h:
            hard.append((section, oid, "mismatch"))
    return hard


def test_wrong_hash_over_resolvable_source_is_hard_fail():
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    wrong = "sha256:" + "0" * 64  # well-formed but not the real digest
    records = {"ksi": {"KSI-TEST-001": {"evidence": [
        {"source_fact": fact, "xEvidenceContentHash": wrong,
         "evidenceLocation": "s3://bucket/key"}]}}, "frr": {}}
    hard = _count_hard(records)
    check("KSI wrong-but-well-formed hash is caught", any(h[2] == "mismatch" for h in hard))


def test_matching_hash_passes():
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    right = evidence_hash(fact)
    records = {"ksi": {"KSI-TEST-002": {"evidence": [
        {"source_fact": fact, "xEvidenceContentHash": right,
         "evidenceLocation": "s3://bucket/key"}]}}, "frr": {}}
    check("matching hash produces no hard failure", not _count_hard(records))


def test_missing_hash_helper_is_hard_fail_not_finding():
    # FAIL-CLOSED: if the canonical evidence hash implementation cannot be
    # imported, a resolvable evidence entry must be a HARD failure - the
    # validator cannot perform the integrity check it claims to. Previously this
    # produced a soft finding and the gate stayed green.
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    e = {"source_fact": fact, "xEvidenceContentHash": "sha256:" + "a" * 64,
         "evidenceLocation": "s3://bucket/key"}
    outcome_ok, _ = ve.classify_entry(e, hash_fn=evidence_hash)
    outcome_none, _ = ve.classify_entry(e, hash_fn=None)
    check("with hash helper, a resolvable entry is verified or hard (not skipped)",
          outcome_ok in ("verified", "hard"))
    check("WITHOUT hash helper, a resolvable entry is a HARD failure",
          outcome_none == "hard")


def test_frr_evidence_is_read():
    fact = {"artifact": "config-snapshot", "value": 42}
    wrong = "sha256:" + "a" * 64
    records = {"frr": {"AFC-CSP-INI": {"extension": {"rule_artifacts": [
        {"source_fact": fact, "xEvidenceContentHash": wrong}]}}}, "ksi": {}}
    seen = [oid for oid, sect, _ in ve.iter_evidence(records) if sect == "frr"]
    check("FRR extension.rule_artifacts is iterated", "AFC-CSP-INI" in seen)
    check("FRR wrong hash is caught", any(h[2] == "mismatch" for h in _count_hard(records)))


def test_absent_signature_stays_verified():
    # Signing is opt-in per deployment; an entry with a correct hash and NO
    # signature is still verified-by-hash, not a failure - WHEN no signer is
    # pinned (or the pinned signer is not in required mode).
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    e = {"source_fact": fact, "xEvidenceContentHash": evidence_hash(fact),
         "evidenceLocation": "s3://bucket/key"}
    outcome, _ = ve.classify_entry(e, hash_fn=evidence_hash)
    check("correct hash, no signature, no pinned signer -> verified", outcome == "verified")


def test_absent_signature_under_required_signer_is_hard():
    # Finding 8 (downgrade): with a trusted signer pinned in signing-required
    # mode, an entry with NO signature is a downgrade to hash-only and must be
    # HARD - an actor who can edit the record cannot strip the signature to
    # weaken verification.
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    e = {"source_fact": fact, "xEvidenceContentHash": evidence_hash(fact),
         "evidenceLocation": "s3://bucket/key"}
    _, pem = _make_keypair()
    required_signer = {"public_key": pem, "key_arn": _TEST_ARN,
                       "public_key_fingerprint": None, "required": True}
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=required_signer)
    check("no signature under a REQUIRED pinned signer -> hard (downgrade blocked)",
          outcome == "hard" and "REQUIRED BUT ABSENT" in msg)


def test_absent_signature_under_optional_signer_is_verified():
    # A pinned signer with signing_required=false explicitly accepts hash-only,
    # so an unsigned entry is still verified.
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    e = {"source_fact": fact, "xEvidenceContentHash": evidence_hash(fact),
         "evidenceLocation": "s3://bucket/key"}
    _, pem = _make_keypair()
    optional_signer = {"public_key": pem, "key_arn": _TEST_ARN,
                       "public_key_fingerprint": None, "required": False}
    outcome, _ = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=optional_signer)
    check("no signature under an OPTIONAL pinned signer -> verified", outcome == "verified")


# --- Real ECDSA signing/verification (findings 7/8) ---
# The old tests used signature="QUJD" (base64 for "ABC") and treated it as a
# valid binding -> verified, which proved only that a blob was attached, NOT
# that the expected signer cryptographically signed the hash. These generate a
# real ECC_NIST_P256 key, produce a DER ECDSA signature over the hash the way
# KMS RAW/ECDSA_SHA_256 does, and verify against an INDEPENDENTLY PINNED key.

_TEST_ARN = "TEST-KMS-KEY-audit-signer-not-an-arn"


def _make_keypair():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return priv, pem


def _sign(priv, content_hash):
    # KMS RAW + ECDSA_SHA_256 hashes the message with SHA-256 and returns a DER
    # signature; reproduce that offline. base64 to match the stored shape.
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    sig = priv.sign(content_hash.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode("ascii")


def _signed_entry(priv, keyid=_TEST_ARN):
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    h = evidence_hash(fact)
    return {"source_fact": fact, "xEvidenceContentHash": h,
            "evidenceLocation": "s3://bucket/key",
            "xEvidenceSignature": {"algorithm": "ECDSA_SHA_256", "keyId": keyid,
                                   "signedHash": h, "signature": _sign(priv, h)}}, h


def test_real_signature_verifies_against_pinned_key():
    priv, pem = _make_keypair()
    e, _ = _signed_entry(priv)
    signer = {"public_key": pem, "key_arn": _TEST_ARN, "public_key_fingerprint": None}
    outcome, _ = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("real ECDSA signature verifies against the pinned key -> verified",
          outcome == "verified")


def test_signature_present_but_no_pinned_signer_is_hard():
    priv, _ = _make_keypair()
    e, _ = _signed_entry(priv)
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=None)
    check("signature present but no pinned signer -> hard (fail closed)",
          outcome == "hard" and "no trusted signer" in msg)


def test_signature_by_untrusted_keyid_is_hard():
    priv, pem = _make_keypair()
    e, _ = _signed_entry(priv, keyid="arn:aws:kms:us-east-1:999:key/attacker")
    signer = {"public_key": pem, "key_arn": _TEST_ARN, "public_key_fingerprint": None}
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("signature whose keyId != pinned ARN -> hard (signer not trusted)",
          outcome == "hard" and "SIGNER NOT TRUSTED" in msg)


def test_signature_by_wrong_key_does_not_verify():
    # A blob 'QUJD' (the old fake) or a signature by a DIFFERENT key must NOT
    # verify against the pinned key.
    priv_attacker, _ = _make_keypair()
    _, pem_trusted = _make_keypair()
    e, _ = _signed_entry(priv_attacker)  # signed by attacker, pinned is trusted
    signer = {"public_key": pem_trusted, "key_arn": _TEST_ARN,
              "public_key_fingerprint": None}
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("signature by a non-pinned key -> hard (SIGNATURE INVALID)",
          outcome == "hard" and "INVALID" in msg)


def test_fake_blob_signature_does_not_verify():
    priv, pem = _make_keypair()
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    h = evidence_hash(fact)
    e = {"source_fact": fact, "xEvidenceContentHash": h,
         "evidenceLocation": "s3://bucket/key",
         "xEvidenceSignature": {"algorithm": "ECDSA_SHA_256", "keyId": _TEST_ARN,
                                "signedHash": h, "signature": "QUJD"}}  # the old fake
    signer = {"public_key": pem, "key_arn": _TEST_ARN, "public_key_fingerprint": None}
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("the old 'QUJD' fake blob no longer passes as verified -> hard",
          outcome == "hard" and ("INVALID" in msg or "ERROR" in msg))


def test_fingerprint_pin_mismatch_is_hard():
    from sign_evidence import public_key_fingerprint
    priv, pem = _make_keypair()
    e, _ = _signed_entry(priv)
    signer = {"public_key": pem, "key_arn": _TEST_ARN,
              "public_key_fingerprint": "sha256:" + "0" * 64}  # wrong fingerprint
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("a wrong pinned-key fingerprint -> hard (second pin catches it)",
          outcome == "hard")
    # And the correct fingerprint verifies.
    signer["public_key_fingerprint"] = public_key_fingerprint(pem)
    outcome2, _ = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("the matching pinned-key fingerprint verifies", outcome2 == "verified")


def test_stale_signature_binding_is_hard():
    # The fact changed after signing: signedHash no longer matches the current
    # content hash. HARD before any crypto.
    priv, pem = _make_keypair()
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    h = evidence_hash(fact)
    old_hash = "sha256:" + "b" * 64
    e = {"source_fact": fact, "xEvidenceContentHash": h,
         "evidenceLocation": "s3://bucket/key",
         "xEvidenceSignature": {"algorithm": "ECDSA_SHA_256", "keyId": _TEST_ARN,
                                "signedHash": old_hash, "signature": _sign(priv, old_hash)}}
    signer = {"public_key": pem, "key_arn": _TEST_ARN, "public_key_fingerprint": None}
    outcome, msg = ve.classify_entry(e, hash_fn=evidence_hash, trusted_signer=signer)
    check("stale signature binding -> hard", outcome == "hard" and "STALE" in msg)


def test_malformed_signature_block_is_hard():
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    h = evidence_hash(fact)
    e = {"source_fact": fact, "xEvidenceContentHash": h,
         "evidenceLocation": "s3://bucket/key",
         "xEvidenceSignature": {"algorithm": "ECDSA_SHA_256"}}  # no sig/keyId/signedHash
    outcome, _ = ve.classify_entry(e, hash_fn=evidence_hash)
    check("signature block missing fields -> hard", outcome == "hard")


def main():
    for t in (test_wrong_hash_over_resolvable_source_is_hard_fail,
              test_matching_hash_passes, test_missing_hash_helper_is_hard_fail_not_finding,
              test_frr_evidence_is_read,
              test_absent_signature_stays_verified,
              test_absent_signature_under_required_signer_is_hard,
              test_absent_signature_under_optional_signer_is_verified,
              test_real_signature_verifies_against_pinned_key,
              test_signature_present_but_no_pinned_signer_is_hard,
              test_signature_by_untrusted_keyid_is_hard,
              test_signature_by_wrong_key_does_not_verify,
              test_fake_blob_signature_does_not_verify,
              test_fingerprint_pin_mismatch_is_hard,
              test_stale_signature_binding_is_hard,
              test_malformed_signature_block_is_hard):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
