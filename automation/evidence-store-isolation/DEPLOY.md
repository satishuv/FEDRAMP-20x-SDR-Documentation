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
