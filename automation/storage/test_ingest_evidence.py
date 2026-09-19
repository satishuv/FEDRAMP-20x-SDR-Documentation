#!/usr/bin/env python3
"""Offline tests for content-addressed, append-only evidence ingestion
(findings 8/9). No network: a fake versioned S3 client models put/get with
per-version bodies."""

import hashlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest_evidence import (  # noqa: E402
    ingest_evidence, verify_ingested, content_key, content_hash, IngestionError)


class FakeVersionedS3:
    """Models a versioned bucket: each PUT to a key creates a new version with
    its own body; GET with VersionId returns that exact version, GET without
    returns the latest."""

    def __init__(self, versioning=True):
        self.versioning = versioning
        self._store = {}       # (bucket, key) -> list of (versionId, body)
        self._counter = 0

    def put_object(self, Bucket, Key, Body, **_kw):
        body = Body.encode("utf-8") if isinstance(Body, str) else bytes(Body)
        self._counter += 1
        vid = f"v{self._counter}"
        self._store.setdefault((Bucket, Key), []).append((vid, body))
        return {"VersionId": vid} if self.versioning else {}

    def get_object(self, Bucket, Key, VersionId=None, **_kw):
        versions = self._store.get((Bucket, Key))
        if not versions:
            raise KeyError("NoSuchKey")
        if VersionId is None:
            _, body = versions[-1]
        else:
            match = [b for (v, b) in versions if v == VersionId]
            if not match:
                raise KeyError("NoSuchVersion")
            body = match[0]
        return {"Body": io.BytesIO(body)}


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    return bool(cond)


def main():
    ok = True
    body = b'{"ident":"KSI-CNA-EDM","status":"pass"}'
    sha = "sha256:" + hashlib.sha256(body).hexdigest()

    # 1. Content-addressed key derives purely from content.
    ok &= check("content_key is evidence/<sha256>.json derived from the bytes",
                content_key(body) == f"evidence/{sha.split(':',1)[1]}.json"
                and content_hash(body) == sha)

    # 2. Ingest captures {bucket,key,versionId,sha256}.
    s3 = FakeVersionedS3()
    prov = ingest_evidence(s3, "audit-evidence", body)
    ok &= check("ingest returns provenance with the content key, a VersionId, and the sha256",
                prov["key"] == content_key(body) and prov["versionId"] == "v1"
                and prov["sha256"] == sha and prov["bucket"] == "audit-evidence")

    # 3. Idempotent content -> same key; different content -> different key
    #    (append-only by construction).
    prov_same = ingest_evidence(s3, "audit-evidence", body)
    other = b'{"ident":"KSI-CNA-EDM","status":"fail"}'
    prov_diff = ingest_evidence(s3, "audit-evidence", other)
    ok &= check("identical content lands at the SAME key; different content at a DIFFERENT key",
                prov_same["key"] == prov["key"] and prov_diff["key"] != prov["key"])

    # 4. verify_ingested reads the PINNED version and confirms the digest.
    ok &= check("verify_ingested passes for a faithfully-stored pinned version",
                verify_ingested(s3, prov) is True)

    # 5. Verify-by-version defeats a same-key shadow PUT: a later PUT of
    #    DIFFERENT bytes to the same key creates a new current version, but the
    #    pinned VersionId still reads the original bytes, so verify still passes
    #    on the original provenance (the shadow cannot replace what we pinned).
    #    (Model the shadow by force-appending a version under the same key.)
    s3._store[("audit-evidence", prov["key"])].append(("v-shadow", b"tampered"))
    ok &= check("a same-key shadow PUT does not change what the pinned VersionId reads",
                verify_ingested(s3, prov) is True)

    # 6. A provenance record whose key is not the content hash is rejected
    #    (append-only invariant broken).
    bad = dict(prov, key="evidence/not-a-hash.json")
    try:
        verify_ingested(s3, bad)
        ok &= check("non-content-addressed key is rejected", False)
    except IngestionError:
        ok &= check("non-content-addressed key is rejected", True)

    # 7. A provenance record whose stored bytes do not match the sha is caught
    #    as a mismatch (verify returns False).
    tampered_prov = {"bucket": "audit-evidence", "key": content_key(b"real"),
                     "versionId": "vX", "sha256": content_hash(b"real")}
    s3._store[("audit-evidence", content_key(b"real"))] = [("vX", b"tampered-bytes")]
    ok &= check("verify_ingested returns False when the pinned bytes do not hash to the record",
                verify_ingested(s3, tampered_prov) is False)

    # 8. A non-versioned bucket (no VersionId) is refused - append-only
    #    provenance requires a version to pin.
    s3_nover = FakeVersionedS3(versioning=False)
    try:
        ingest_evidence(s3_nover, "unversioned", body)
        ok &= check("ingest refuses a non-versioned bucket (no VersionId)", False)
    except IngestionError:
        ok &= check("ingest refuses a non-versioned bucket (no VersionId)", True)

    print(f"\n{'OK' if ok else 'FAILED'}: ingest_evidence tests")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
