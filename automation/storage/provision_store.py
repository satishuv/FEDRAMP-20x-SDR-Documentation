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
                 retention_days=None, dry_run=False,
                 object_lock_mode="GOVERNANCE", object_lock_days=365):
    """Ensure the durable store bucket exists with versioning ENABLED.

    Safety-additive only: creates the bucket if absent, enables versioning if
    not already Enabled, and (optionally) configures Object Lock. Never
    suspends versioning, never deletes anything. Returns a ProvisionResult.
    """
    result = ProvisionResult()
    result.dry_run = dry_run
    s3 = session.client("s3")

    exists = _bucket_exists(s3, bucket)

    # 1. Create the bucket if it does not exist. Object Lock at creation still
    #    needs ObjectLockEnabledForBucket; the DEFAULT RETENTION rule is applied
    #    in step 3 (after versioning), for both new and existing buckets.
    if not exists:
        create_args = {"Bucket": bucket}
        # us-east-1 must NOT send a LocationConstraint; every other region must.
        if region and region != "us-east-1":
            create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}
        if object_lock:
            create_args["ObjectLockEnabledForBucket"] = True
        if not dry_run:
            s3.create_bucket(**create_args)
        result.changed(f"create bucket '{bucket}'"
                       + (f" in {region}" if region else "")
                       + (" with Object Lock enabled" if object_lock else ""))
    else:
        result.noop(f"bucket '{bucket}' already exists")

    # 2. Enable versioning (the core requested feature, and a PREREQUISITE for
    #    Object Lock). Must happen BEFORE any Object Lock configuration.
    #    Idempotent; never suspends.
    current = _versioning_status(s3, bucket) if exists else None
    if current == "Enabled":
        result.noop(f"versioning already Enabled on '{bucket}'")
    else:
        if not dry_run:
            s3.put_bucket_versioning(
                Bucket=bucket,
                VersioningConfiguration={"Status": "Enabled"})
        prior = f" (was {current})" if current else ""
        result.changed(f"enable versioning on '{bucket}'{prior}")

    # 2b. Object Lock default retention (AFTER versioning is enabled). Applies to
    #     both a newly-created Object-Lock bucket and an existing versioned one.
    #     If the caller explicitly asked for --object-lock and AWS refuses it,
    #     this RAISES (a refused WORM request must not be a silent success).
    if object_lock and not dry_run:
        try:
            s3.put_object_lock_configuration(
                Bucket=bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {
                        "Mode": object_lock_mode,
                        "Days": object_lock_days,
                    }},
                })
            result.changed(f"configure Object Lock default retention on '{bucket}' "
                           f"({object_lock_mode}, {object_lock_days} days)")
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            raise RuntimeError(
                f"Object Lock was requested (--object-lock) but could not be "
                f"configured on '{bucket}' ({code}). Object Lock requires "
                "versioning (now enabled) and appropriate permissions; refusing "
                "to report a successful provisioning run with Object Lock absent.")
    elif object_lock and dry_run:
        result.noop(f"would configure Object Lock default retention on '{bucket}' "
                    f"({object_lock_mode}, {object_lock_days} days)")

    # 3. Optional lifecycle retention. Provider policy choice; only added when
    #    an explicit retention is passed. Never a default.
    if retention_days is not None:
        if retention_days <= 0:
            raise ValueError("--retention-days must be a positive integer")
        our_rule = {
            "ID": "sdr-store-retention",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "NoncurrentVersionExpiration": {"NoncurrentDays": retention_days},
            "Expiration": {"Days": retention_days},
        }
        # PutBucketLifecycleConfiguration REPLACES the entire configuration, so a
        # blind PUT would wipe a customer's existing lifecycle rules. Fetch the
        # current rules first and preserve every rule that is not ours; then
        # replace/add only the sdr-store-retention rule. Safety-additive.
        existing = []
        try:
            resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            existing = [r for r in (resp.get("Rules") or [])
                        if r.get("ID") != "sdr-store-retention"]
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            # ONLY a confirmed "no lifecycle configuration" means empty. Any
            # other error - including an unknown one with no error code - must
            # NOT be treated as empty, or a subsequent PUT could clobber unknown
            # existing customer rules.
            if code == "NoSuchLifecycleConfiguration":
                existing = []  # confirmed empty: safe to create the rule
            else:
                # --retention-days was EXPLICITLY requested (we are inside
                # `if retention_days is not None`) but the existing lifecycle
                # configuration could not be read, so we can neither preserve it
                # nor safely apply the requested retention. A successful (exit 0)
                # run must mean the requested retention was actually applied, so
                # fail LOUDLY rather than reporting success with retention absent.
                # This matches the fail-closed contract of the Object Lock path.
                raise RuntimeError(
                    f"--retention-days ({retention_days}) was requested, but the "
                    f"existing lifecycle configuration on '{bucket}' could not be "
                    f"read ({code or 'unknown error'}). Refusing to overwrite an "
                    "unknown lifecycle policy or to report success without the "
                    "requested retention applied.")
        merged = existing + [our_rule]
        if not dry_run:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={"Rules": merged})
        preserved = f", preserving {len(existing)} existing rule(s)" if existing else ""
        result.changed(
            f"set lifecycle retention to {retention_days} days on '{bucket}' "
            f"(current and noncurrent versions){preserved}")

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
                    help="Enable Object Lock (WORM). Applied at creation for a new "
                         "bucket, or via PutObjectLockConfiguration on an existing "
                         "versioned bucket, with a default retention rule")
    ap.add_argument("--object-lock-mode", default="GOVERNANCE",
                    choices=["GOVERNANCE", "COMPLIANCE"],
                    help="Object Lock default retention mode (default GOVERNANCE)")
    ap.add_argument("--object-lock-days", type=int, default=365,
                    help="Object Lock default retention period in days (default 365)")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="Optional lifecycle retention in days (provider policy "
                         "choice; 20x's KSI metric-history window is ~1 year). "
                         "This is lifecycle expiry, distinct from Object Lock "
                         "retention, and it merges with existing lifecycle rules")
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
            object_lock_mode=args.object_lock_mode,
            object_lock_days=args.object_lock_days,
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
