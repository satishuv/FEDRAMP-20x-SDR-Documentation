# Evidence-store isolation (reference stack)

This is a **reference**, not a turnkey deploy. It shows the account topology
that makes the evidence chain of custody real: the evidence store and its
signing key live **outside the assessed accounts' blast radius**, so a
privileged actor in an assessed account can neither rewrite a signed evidence
record nor forge a new signature.

## Why this exists

Versioning and a content hash give tamper-**evidence**. A KMS signature over the
hash gives non-repudiation **only if** the signing key is out of reach of the
identity that could rewrite the record. That "out of reach" is an account
topology decision, not something a single script can enforce. This stack
demonstrates the intended topology.

## What it provisions (in a dedicated audit/evidence account)

| Mechanism | Control support |
|---|---|
| Evidence bucket with versioning + Object Lock (COMPLIANCE mode) | AU-09, AU-09 (02), AU-09 (03), AU-11 |
| Bucket policy denying assessed collector roles any Put/Delete/lock mutation | AU-09, AU-09 (04) |
| Narrow cross-account writer role (append-only PutObject) | AU-09 (04) |
| Asymmetric KMS signing key; `kms:Sign` granted only to a separate signer, denied to collectors | AU-09 (02/03/04), AU-10 |
| Server access logging to a separate log bucket | AU-09 (04), KSI-MLA-ALA |

Control identifiers are the ones verified in
`traceability/evidence-store-controls.json` against the pinned CR26 dataset.

## Access logging is configured to actually deliver (not just declared)

S3 server access logging fails silently if the destination bucket is not set up
exactly as AWS requires. This stack sets up all three prerequisites, and
`validate_isolation_stack.py` asserts them (an earlier version only checked that
`LoggingConfiguration` existed, which passed while delivery was broken):

- The log bucket carries a **bucket policy** granting the logging service
  principal (`logging.s3.amazonaws.com`) `s3:PutObject`, scoped by
  `aws:SourceArn` / `aws:SourceAccount` to the evidence bucket. With Bucket
  Owner Enforced (ACLs disabled), a bucket policy is the only way to authorize
  log delivery.
- The log bucket uses **SSE-S3 (AES256)**, never SSE-KMS. AWS does not deliver
  server access logs to a bucket with SSE-KMS default encryption.
- The log bucket has **no Object Lock and no default retention** - S3 refuses an
  Object-Lock bucket as a log destination. Only the evidence bucket is locked.

## Append-only means content-addressed keys, not a blanket PutObject

Object Lock protects the **existing** version of a key, but `s3:PutObject` to an
existing key still creates a **new version**, and a later `GET` of that key
resolves to the newer version. So a blanket `.../*` PutObject grant is not
genuinely append-only. The writer is therefore scoped to the content-addressed
prefix `evidence/<sha256>.json`: the key IS the content hash, so re-putting
identical content is the same key and different content necessarily lands at a
different key - a content key's `GET` is stable. The ingestion path records the
returned `VersionId` and the content hash into release provenance, binding a
specific immutable version rather than "whatever is latest under this key".

That ingestion path is implemented in
[`automation/storage/ingest_evidence.py`](../storage/ingest_evidence.py):
`ingest_evidence()` derives the `evidence/<sha256>.json` key from the content
(callers do not choose the key, so the key can never disagree with the bytes),
PUTs to the versioned bucket, and captures the returned `VersionId` into a
`{bucket, key, versionId, sha256}` provenance record. `verify_ingested()`
re-reads that EXACT pinned `VersionId` (not the mutable current version) and
recomputes the digest, so a later same-key shadow PUT cannot replace what a
provenance record pinned. The bucket policy scopes the write; the ingestion
code enforces the content-address and pins the version.

## Deploy

```bash
aws cloudformation deploy \
  --template-file automation/evidence-store-isolation/cloudformation.yaml \
  --stack-name sdr-evidence-store-isolation \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      EvidenceBucketName=my-org-sdr-evidence \
      AssessedCollectorRoleArns=arn:aws:iam::<ASSESSED_ACCT>:role/sdr-collector \
      CrossAccountWriterRoleArn=arn:aws:iam::<INGEST_ACCT>:role/sdr-evidence-writer \
      SignerPrincipalArn=arn:aws:iam::<AUDIT_ACCT>:role/sdr-evidence-signer \
  --profile <audit-account-deploy>
```

Then pass the `SigningKeyArn` output to the signer:

```bash
# The signer principal (NOT the collector) runs this step.
python automation/collectors/sign_evidence.py  # via attach_signature(entry, kms, key_id)
```

## The boundary, stated plainly

Non-repudiation holds only if the audit account is genuinely administered
separately from the assessed accounts. If one human is admin of both, this
topology documents the intent but does not enforce it. Separation of duties on
the audit account is an organizational control this template cannot create for
you - it is the one part that is a process commitment, not code.

## What is provider-specific (and why this is a reference)

The account ids, OU structure, cross-account trust, and whether the audit
account is in the provider's own Organization or a managed one are all provider
decisions. Over-fitting a specific topology here would be speculative; this
template demonstrates the invariants (deny-collector-sign, deny-collector-
mutation, WORM, separate logging) and leaves the topology to you.
