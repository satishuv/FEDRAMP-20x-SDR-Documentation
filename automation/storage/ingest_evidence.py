#!/usr/bin/env python3
"""Content-addressed, append-only evidence ingestion with VersionId provenance.

Findings 8/9. The isolation-stack CloudFormation and DEPLOY.md DESCRIBE an
append-only evidence store: the writer is scoped to the content-addressed prefix
`evidence/<sha256>.json`, "the key IS the content hash, so re-putting identical
content is idempotent and different content necessarily lands at a different
key," and "the ingestion path records the returned VersionId and the content
hash into release provenance." That ingestion path did not exist - the bucket
policy alone cannot enforce key == SHA256(body), and a plain GET on Object Lock
returns the CURRENT version, so a writer with PutObject on the same key could
shadow evidence. This module is that missing ingestion path.

What it guarantees, in code (not just narrated):

  1. CONTENT-ADDRESSED KEY. The object key is derived from the SHA-256 of the
     exact bytes: `evidence/<sha256hex>.json`. The key cannot disagree with the
     content because the key IS a function of the content. Callers do not choose
     the key.

  2. APPEND-ONLY BY CONSTRUCTION. Because the key is the content hash, different
     content always lands at a different key; identical content is idempotent.
     A caller cannot overwrite one logical evidence item with different bytes -
     different bytes are a different key.

  3. VERSIONID PROVENANCE. PutObject returns a VersionId (buckets are versioned
     by provision_store). Ingestion captures {bucket, key, versionId, sha256}
     as a provenance record, so verification can GET that EXACT version
     (VersionId=...) rather than the mutable current version, and recompute the
     hash. This closes the "plain GET returns the latest object" gap.

  4. VERIFY-BY-VERSION. verify_ingested() re-reads the pinned VersionId and
     recomputes the digest; a mismatch is a hard error. This is what makes the
     stored provenance meaningful rather than a claim.

Trust boundary, unchanged: this stores bytes and records where they landed. It
never sets a status, writes an assessment, or makes a determination.

Offline-testable: pass any object exposing put_object / get_object (a boto3 S3
client or a fake). No network in tests.
"""

import argparse
import hashlib
import json
import sys


EVIDENCE_PREFIX = "evidence/"


class IngestionError(RuntimeError):
    """A refused or failed ingestion must never be a silent success."""


def content_hash(body):
    """SHA-256 over the exact bytes, as 'sha256:<64 hex>'. Accepts bytes or a
    str (encoded UTF-8). This is the identity of the evidence content."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not isinstance(body, (bytes, bytearray)):
        raise IngestionError("evidence body must be bytes or str")
    return "sha256:" + hashlib.sha256(bytes(body)).hexdigest()


def content_key(body):
    """The content-addressed object key for a body: evidence/<sha256hex>.json.
    The key is a pure function of the content, so it can never disagree with it
    (append-only by construction)."""
    return f"{EVIDENCE_PREFIX}{content_hash(body).split(':', 1)[1]}.json"


def ingest_evidence(s3_client, bucket, body):
    """PUT one evidence body at its content-addressed key and capture the
    returned VersionId as provenance.

    s3_client : object exposing put_object(Bucket, Key, Body, ...) -> resp with
                a 'VersionId'. On a versioned bucket (provision_store enables
                versioning) PutObject returns the new version's id.
    bucket    : the evidence bucket (in the provider's own / audit account).
    body      : the exact evidence bytes (bytes or str).

    Returns a provenance record: {"bucket", "key", "versionId", "sha256"}.
    Raises IngestionError if the bucket has no versioning (no VersionId
    returned) - without a VersionId the append-only/verify-by-version guarantee
    cannot hold, so refusing is correct rather than recording a null version."""
    if not bucket:
        raise IngestionError("bucket is required")
    if isinstance(body, str):
        body = body.encode("utf-8")
    sha = content_hash(body)
    key = content_key(body)
    try:
        resp = s3_client.put_object(
            Bucket=bucket, Key=key, Body=body,
            ContentType="application/json",
            # Belt-and-braces integrity: also record the hash as object metadata,
            # so an out-of-band reader can see the intended digest.
            Metadata={"sha256": sha.split(":", 1)[1]},
        )
    except Exception as e:  # noqa: BLE001 - normalize any client failure
        raise IngestionError(
            f"put_object failed for s3://{bucket}/{key} ({type(e).__name__}); "
            "refusing to report ingested evidence without a stored object") from e
    version_id = (resp or {}).get("VersionId")
    if not version_id:
        raise IngestionError(
            f"s3://{bucket}/{key} PutObject returned no VersionId; the bucket is "
            "not versioned. Run automation/storage/provision_store.py to enable "
            "versioning (and Object Lock) before ingesting evidence - append-only "
            "provenance requires a VersionId to pin.")
    return {"bucket": bucket, "key": key, "versionId": version_id, "sha256": sha}


def verify_ingested(s3_client, provenance):
    """Re-read the EXACT pinned version and confirm the content still hashes to
    the recorded digest. This is what makes the provenance record load-bearing:
    it reads VersionId=<recorded> (not the mutable current version), so a later
    same-key PUT of different bytes cannot shadow it.

    Returns True on match. Raises IngestionError on a malformed provenance
    record or a read failure; returns False on a digest mismatch (the pinned
    version's bytes are not what was recorded - tampering or corruption)."""
    if not isinstance(provenance, dict):
        raise IngestionError("provenance must be a dict")
    bucket = provenance.get("bucket")
    key = provenance.get("key")
    version_id = provenance.get("versionId")
    sha = provenance.get("sha256")
    if not (bucket and key and version_id and sha):
        raise IngestionError(
            "provenance missing bucket/key/versionId/sha256")
    # The key must itself be the content hash (append-only invariant): a key
    # that does not encode the recorded sha256 is not a valid content address.
    expected_key = f"{EVIDENCE_PREFIX}{sha.split(':', 1)[1]}.json"
    if key != expected_key:
        raise IngestionError(
            f"provenance key {key!r} is not the content-addressed key for "
            f"{sha!r} (expected {expected_key!r}); the record is not append-only")
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
        body = resp["Body"].read() if hasattr(resp.get("Body"), "read") else resp.get("Body")
    except Exception as e:  # noqa: BLE001
        raise IngestionError(
            f"get_object failed for s3://{bucket}/{key}?versionId={version_id} "
            f"({type(e).__name__}); cannot verify the pinned evidence version") from e
    if body is None:
        raise IngestionError(
            f"s3://{bucket}/{key}?versionId={version_id} returned no body")
    return content_hash(body) == sha


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Ingest an evidence file at its content-addressed key and "
                    "print the {bucket,key,versionId,sha256} provenance record. "
                    "Append-only by construction; requires a versioned bucket.")
    ap.add_argument("--bucket", required=True, help="Evidence bucket (own/audit account)")
    ap.add_argument("--file", required=True, help="Path to the evidence file to ingest")
    ap.add_argument("--profile", default=None, help="AWS profile (least-privilege s3:PutObject)")
    ap.add_argument("--region", default=None)
    ap.add_argument("--verify", action="store_true",
                    help="After PUT, re-read the pinned version and confirm the digest")
    args = ap.parse_args(argv)

    try:
        with open(args.file, "rb") as f:
            body = f.read()
    except OSError as e:
        print(f"Cannot read {args.file}: {e}")
        return 1

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        s3 = session.client("s3")
        session.client("sts").get_caller_identity()
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        print(f"No usable AWS credentials ({type(e).__name__}); nothing done.")
        return 1

    try:
        prov = ingest_evidence(s3, args.bucket, body)
        if args.verify and not verify_ingested(s3, prov):
            print("VERIFY FAILED: the pinned version does not hash to the recorded digest.")
            return 2
    except IngestionError as e:
        print(f"Ingestion refused: {e}")
        return 2

    print(json.dumps(prov, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
