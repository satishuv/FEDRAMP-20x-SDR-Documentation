# Offline tests for the durable-store provisioner (automation/storage).
#
# No network, no boto3: a FakeS3 records the calls the module makes so we can
# assert the safety invariants:
#   - versioning is ENABLED (never Suspended)
#   - re-running is idempotent (already-Enabled -> no put_bucket_versioning)
#   - a missing bucket is created; an existing one is not recreated
#   - no destructive call is ever made (no delete_*, no Suspended status)
#   - an existing bucket owned by someone else is refused, not created over
#
# Run: python automation/storage/provision_store.py's tests via
#   python -m pytest automation/storage/test_provision_store.py
# or the plain runner at the bottom: python automation/storage/test_provision_store.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provision_store import ensure_store, _error_code  # noqa: E402


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Records every call. head_bucket behavior is driven by `exists`/`owner`."""

    def __init__(self, exists=False, versioning=None, forbidden=False):
        self._exists = exists
        self._versioning = versioning  # None | "Enabled" | "Suspended"
        self._forbidden = forbidden
        self.calls = []

    def head_bucket(self, Bucket):
        self.calls.append(("head_bucket", Bucket))
        if self._forbidden:
            raise FakeClientError("403")
        if not self._exists:
            raise FakeClientError("404")
        return {}

    def create_bucket(self, **kw):
        self.calls.append(("create_bucket", kw))
        self._exists = True
        return {}

    def get_bucket_versioning(self, Bucket):
        self.calls.append(("get_bucket_versioning", Bucket))
        return {"Status": self._versioning} if self._versioning else {}

    def put_bucket_versioning(self, Bucket, VersioningConfiguration):
        self.calls.append(("put_bucket_versioning", Bucket, VersioningConfiguration))
        self._versioning = VersioningConfiguration["Status"]
        return {}

    def put_bucket_lifecycle_configuration(self, Bucket, LifecycleConfiguration):
        self.calls.append(("put_bucket_lifecycle_configuration", Bucket,
                           LifecycleConfiguration))
        return {}


class FakeSession:
    def __init__(self, s3):
        self._s3 = s3
        self.region_name = "us-east-1"

    def client(self, name):
        assert name == "s3", f"only s3 expected, got {name}"
        return self._s3


def _names(s3):
    return [c[0] for c in s3.calls]


def test_new_bucket_gets_created_and_versioned():
    s3 = FakeS3(exists=False)
    r = ensure_store(FakeSession(s3), "b", region="us-east-1")
    assert ("create_bucket", {"Bucket": "b"}) in s3.calls
    # versioning turned on
    puts = [c for c in s3.calls if c[0] == "put_bucket_versioning"]
    assert len(puts) == 1
    assert puts[0][2] == {"Status": "Enabled"}
    assert any("enable versioning" in a for a in r.actions)


def test_versioning_is_enabled_never_suspended():
    for start in (None, "Suspended"):
        s3 = FakeS3(exists=True, versioning=start)
        ensure_store(FakeSession(s3), "b")
        puts = [c for c in s3.calls if c[0] == "put_bucket_versioning"]
        assert puts, f"expected versioning to be set from {start}"
        assert all(c[2]["Status"] == "Enabled" for c in puts)
        # never suspends
        assert all(c[2]["Status"] != "Suspended" for c in puts)


def test_idempotent_when_already_enabled():
    s3 = FakeS3(exists=True, versioning="Enabled")
    r = ensure_store(FakeSession(s3), "b")
    assert not any(c[0] == "put_bucket_versioning" for c in s3.calls), \
        "must not re-put versioning when already Enabled"
    assert any("already Enabled" in a for a in r.already)


def test_existing_bucket_not_recreated():
    s3 = FakeS3(exists=True, versioning="Enabled")
    ensure_store(FakeSession(s3), "b")
    assert not any(c[0] == "create_bucket" for c in s3.calls)


def test_non_us_east_1_sends_location_constraint():
    s3 = FakeS3(exists=False)
    ensure_store(FakeSession(s3), "b", region="us-west-2")
    create = [c for c in s3.calls if c[0] == "create_bucket"][0]
    assert create[1]["CreateBucketConfiguration"] == {"LocationConstraint": "us-west-2"}


def test_us_east_1_omits_location_constraint():
    s3 = FakeS3(exists=False)
    ensure_store(FakeSession(s3), "b", region="us-east-1")
    create = [c for c in s3.calls if c[0] == "create_bucket"][0]
    assert "CreateBucketConfiguration" not in create[1]


def test_object_lock_only_at_creation():
    s3 = FakeS3(exists=False)
    ensure_store(FakeSession(s3), "b", region="us-east-1", object_lock=True)
    create = [c for c in s3.calls if c[0] == "create_bucket"][0]
    assert create[1]["ObjectLockEnabledForBucket"] is True


def test_forbidden_bucket_is_refused_not_created_over():
    s3 = FakeS3(forbidden=True)
    raised = False
    try:
        ensure_store(FakeSession(s3), "b")
    except PermissionError:
        raised = True
    assert raised, "an inaccessible existing bucket must raise, not be created over"
    assert not any(c[0] == "create_bucket" for c in s3.calls)


def test_retention_only_when_explicit():
    # No retention -> no lifecycle call.
    s3 = FakeS3(exists=True, versioning="Enabled")
    ensure_store(FakeSession(s3), "b")
    assert not any(c[0] == "put_bucket_lifecycle_configuration" for c in s3.calls)
    # Explicit retention -> lifecycle call with that many days.
    s3b = FakeS3(exists=True, versioning="Enabled")
    ensure_store(FakeSession(s3b), "b", retention_days=365)
    lc = [c for c in s3b.calls if c[0] == "put_bucket_lifecycle_configuration"][0]
    rule = lc[2]["Rules"][0]
    assert rule["Expiration"]["Days"] == 365
    assert rule["NoncurrentVersionExpiration"]["NoncurrentDays"] == 365


def test_bad_retention_rejected():
    s3 = FakeS3(exists=True, versioning="Enabled")
    raised = False
    try:
        ensure_store(FakeSession(s3), "b", retention_days=0)
    except ValueError:
        raised = True
    assert raised


def test_no_destructive_calls_ever():
    # Across every scenario, the module must never call a delete/suspend verb.
    for kw in ({"exists": False},
               {"exists": True, "versioning": None},
               {"exists": True, "versioning": "Suspended"},
               {"exists": True, "versioning": "Enabled"}):
        s3 = FakeS3(**kw)
        ensure_store(FakeSession(s3), "b", region="us-east-1")
        for name in _names(s3):
            assert not name.startswith("delete_"), f"destructive call {name}"


def test_dry_run_makes_no_mutating_calls():
    s3 = FakeS3(exists=False)
    r = ensure_store(FakeSession(s3), "b", region="us-east-1", dry_run=True)
    mutating = {"create_bucket", "put_bucket_versioning",
                "put_bucket_lifecycle_configuration"}
    assert not (mutating & set(_names(s3))), "dry-run must not mutate"
    assert r.dry_run and r.actions, "dry-run should still report intended actions"


def _run_all():
    fns = [g for n, g in sorted(globals().items())
           if n.startswith("test_") and callable(g)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} storage-provisioner tests passed.")


if __name__ == "__main__":
    _run_all()
