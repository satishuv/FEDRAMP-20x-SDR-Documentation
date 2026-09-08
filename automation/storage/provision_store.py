# Deploy-time provisioning for the durable metric-history / facts store.
#
# The collectors and the metric appender write locally by default. When a
# provider wires the living-SDR loop into their own account, the facts and the
# per-KSI metric history need to persist in an in-boundary, tamper-resistant
# store (see docs/automation.md "Persistence and retention"). This module
# provisions that store: an S3 bucket in the provider's OWN account with
# **bucket versioning enabled**, and optionally Object Lock (WORM) for
# write-once tamper-evidence.
#
# Why this is a separate module from the collectors:
#   - The collectors are read-only by construction. This is the one deploy-time
#     WRITE step, so it lives on its own, is opt-in, and must be run explicitly.
#   - It is SAFETY-ADDITIVE ONLY. It creates the bucket if absent and turns
#     versioning ON. It NEVER suspends versioning, never disables Object Lock,
#     never deletes a bucket or an object, and never touches encryption or
#     public-access settings destructively (it only tightens them). Re-running
#     it is idempotent: an already-versioned bucket is left as-is.
#
# Trust boundary, unchanged: this provisions storage. It never writes the
# record store, never sets an implementation_status, never writes an
# assessment. It moves no compliance verdict.
#
# Retention note: FedRAMP 20x's governing window for the KSI metric history
# (SDR-CSX-KMT) is up to one year. This module does NOT invent a 7-year
# immutable policy; a lifecycle/retention period is a provider policy choice
# passed in explicitly via --retention-days (default None = no lifecycle rule
# added, provider decides).
#
# Offline-testable: pass any object exposing .client(name) (a boto3 Session or
# a fake). No network in tests.
#
# Usage:
#   python automation/storage/provision_store.py --bucket my-sdr-store [--profile NAME]
#       [--region REGION] [--object-lock] [--retention-days N] [--dry-run]

import argparse
import sys


class ProvisionResult:
    """Structured, printable outcome of a provisioning run."""

    def __init__(self):
        self.actions = []      # what was actually changed
        self.already = []      # what was already in the desired state
        self.dry_run = False

    def changed(self, msg):
        self.actions.append(msg)

    def noop(self, msg):
        self.already.append(msg)

    def summary(self):
        lines = []
        prefix = "would " if self.dry_run else ""
        for a in self.actions:
            lines.append(f"  [{prefix}change] {a}")
        for a in self.already:
            lines.append(f"  [ok] {a}")
        return "\n".join(lines) if lines else "  (nothing to do)"


def _bucket_exists(s3, bucket):
    """True if the bucket exists AND is owned by the caller. A 404 means it can
    be created; a 403 means it exists but belongs to someone else, which is a
    hard error rather than something to silently create over."""
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except Exception as e:  # noqa: BLE001 - normalize botocore ClientError codes
        code = _error_code(e)
        if code in ("404", "NoSuchBucket", "NotFound"):
            return False
        if code in ("403", "Forbidden", "AccessDenied"):
            raise PermissionError(
                f"Bucket '{bucket}' exists but is not accessible to this "
                f"identity ({code}). Refusing to proceed.")
        raise


def _error_code(exc):
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", type(exc).__name__)
    return type(exc).__name__


def _versioning_status(s3, bucket):
    resp = s3.get_bucket_versioning(Bucket=bucket)
    return resp.get("Status")  # "Enabled", "Suspended", or None (never set)


def ensure_store(session, bucket, region=None, object_lock=False,
                 retention_days=None, dry_run=False):
    """Ensure the durable store bucket exists with versioning ENABLED.

    Safety-additive only: creates the bucket if absent, enables versioning if
    not already Enabled, and (optionally) configures Object Lock. Never
    suspends versioning, never deletes anything. Returns a ProvisionResult.
    """
    result = ProvisionResult()
    result.dry_run = dry_run
    s3 = session.client("s3")

    exists = _bucket_exists(s3, bucket)

    # 1. Create the bucket if it does not exist.
    if not exists:
        create_args = {"Bucket": bucket}
        # us-east-1 must NOT send a LocationConstraint; every other region must.
        if region and region != "us-east-1":
            create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}
        # Object Lock can only be turned on at creation time.
        if object_lock:
            create_args["ObjectLockEnabledForBucket"] = True
        if not dry_run:
            s3.create_bucket(**create_args)
        result.changed(f"create bucket '{bucket}'"
                       + (f" in {region}" if region else "")
                       + (" with Object Lock enabled" if object_lock else ""))
    else:
        result.noop(f"bucket '{bucket}' already exists")
        if object_lock:
            # Object Lock cannot be enabled after creation on an existing bucket
            # with objects; surface this rather than silently no-op.
            result.noop("Object Lock requested but bucket already exists; "
                        "Object Lock can only be enabled at creation time "
                        "(recreate the bucket empty to add it)")

    # 2. Enable versioning (the core requested feature). Idempotent.
    current = None
    if exists:
        current = _versioning_status(s3, bucket)
    if current == "Enabled":
        result.noop(f"versioning already Enabled on '{bucket}'")
    else:
        if not dry_run:
            s3.put_bucket_versioning(
                Bucket=bucket,
                VersioningConfiguration={"Status": "Enabled"})
        prior = f" (was {current})" if current else ""
        result.changed(f"enable versioning on '{bucket}'{prior}")

    # 3. Optional lifecycle retention. Provider policy choice; only added when
    #    an explicit retention is passed. Never a default.
    if retention_days is not None:
        if retention_days <= 0:
            raise ValueError("--retention-days must be a positive integer")
        if not dry_run:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={"Rules": [{
                    "ID": "sdr-store-retention",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": retention_days},
                    "Expiration": {"Days": retention_days},
                }]})
        result.changed(
            f"set lifecycle retention to {retention_days} days on '{bucket}' "
            "(current and noncurrent versions)")

    return result


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Provision the durable metric-history/facts store: an "
                    "S3 bucket with versioning enabled (safety-additive, "
                    "idempotent). Deploy-time write step, opt-in.")
    ap.add_argument("--bucket", required=True,
                    help="Target S3 bucket name in the provider's own account")
    ap.add_argument("--profile", default=None,
                    help="AWS profile (least-privilege with s3 write on this bucket)")
    ap.add_argument("--region", default=None,
                    help="Region to create the bucket in (defaults to profile/env)")
    ap.add_argument("--object-lock", action="store_true",
                    help="Enable Object Lock (WORM) at bucket creation for "
                         "write-once tamper-evidence")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="Optional lifecycle retention in days (provider policy "
                         "choice; 20x's KSI metric-history window is ~1 year)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would change without calling AWS")
    args = ap.parse_args(argv)

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ident = session.client("sts").get_caller_identity()
    except (botocore.exceptions.ProfileNotFound,
            botocore.exceptions.NoCredentialsError,
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError) as e:
        print(f"No usable AWS credentials ({type(e).__name__}); nothing done. "
              "Configure a least-privilege profile with s3 write on the target "
              "bucket and re-run.")
        return 1

    region = args.region or session.region_name
    print(f"Identity: {ident.get('Arn', '(unknown)')}")
    print(f"Target bucket: {args.bucket}"
          + (f" ({region})" if region else "") + "\n")

    try:
        result = ensure_store(
            session, args.bucket, region=region,
            object_lock=args.object_lock,
            retention_days=args.retention_days,
            dry_run=args.dry_run)
    except (PermissionError, ValueError) as e:
        print(f"Refusing to proceed: {e}")
        return 2
    except Exception as e:  # noqa: BLE001 - surface AWS errors cleanly
        print(f"Provisioning failed ({type(e).__name__}: {_error_code(e)}).")
        return 2

    print(result.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
