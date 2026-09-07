"""Multi-account, multi-region evidence fan-out (read-only).

The width lever for a large FedRAMP boundary: a 400-service estate is almost
always many AWS accounts across an AWS Organization. This module assumes a
READ-ONLY role into each target account and runs every collector across the
chosen regions in parallel, tagging each fact with its account and region.

Read-only by construction:
  - The only privileged call is sts:AssumeRole into a role the operator names;
    that role must itself grant only the READ_ONLY_ACTIONS the collectors use.
  - Admin-looking role names are refused, mirroring the single-account driver.
  - One account or region failing yields an ERROR fact for that scope, never a
    crash and never a sunk aggregate: partial evidence is still evidence.

This module builds sessions and fans out; it does not decide statuses and never
writes the record store. Facts are telemetry.

Usage (library):
    from collect_multi_account import collect_across_accounts
    facts = collect_across_accounts(
        accounts=["111122223333", "444455556666"],
        role_name="FedRampReadOnly",
        regions=["us-east-1", "us-west-2"],
        base_session=boto3.Session(),
    )

Usage (CLI):
    python collect_multi_account.py --accounts 111122223333,444455556666 \
        --role-name FedRampReadOnly --regions us-east-1,us-west-2
"""
import argparse
import concurrent.futures as cf
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors as _collectors  # noqa: E402

# Default worker cap: enough to fan out a large estate without hammering the
# host or tripping API rate limits. Tunable per call.
DEFAULT_MAX_WORKERS = 16


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scope_error_fact(account, region, detail):
    """A single account/region scope failed to even start: record it as one
    ERROR fact rather than dropping the scope silently."""
    return {
        "service": "_scope",
        "check": "assume_role",
        "status": "ERROR",
        "detail": detail[:480],
        "region": region,
        "account": account,
        "collected_at": _now(),
    }


def assume_role_session(base_session, account, role_name, region,
                        session_name="fedramp-sdr-collector"):
    """Return a boto3 Session for `account` via sts:AssumeRole into `role_name`.

    Refuses admin-looking role names: evidence collection must use a read-only
    role, not an administrative one. Raises on failure; callers convert that
    into a scope ERROR fact so one bad account cannot sink the run.
    """
    if "admin" in role_name.lower():
        raise ValueError(f"Refusing an admin-looking role name: {role_name}. "
                         "Use a read-only role.")
    import boto3
    sts = base_session.client("sts")
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    creds = sts.assume_role(RoleArn=role_arn,
                            RoleSessionName=session_name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _collect_one_scope(base_session, account, role_name, region, collectors):
    """Assume into one account and run every collector for one region.
    Returns a list of account-tagged facts; never raises."""
    try:
        session = assume_role_session(base_session, account, role_name, region)
    except Exception as e:  # noqa: BLE001 - a bad account must not sink the run
        return [_scope_error_fact(account, region,
                                  f"{type(e).__name__}: {e}")]
    facts = []
    for name, fn in collectors:
        try:
            svc_facts = fn(session, region)
        except Exception as e:  # noqa: BLE001 - contract: collectors don't raise,
            # but defend anyway so one service cannot sink the account.
            svc_facts = [{
                "service": name, "check": "collector", "status": "ERROR",
                "detail": type(e).__name__, "region": region,
                "collected_at": _now(),
            }]
        for f in svc_facts:
            f["account"] = account  # tag provenance
            facts.append(f)
    return facts


def collect_across_accounts(accounts, role_name, regions, base_session=None,
                            collectors=None, max_workers=DEFAULT_MAX_WORKERS):
    """Fan every collector across every (account, region) scope in parallel.

    Returns a flat list of account+region-tagged facts. Deterministic in
    membership (every scope contributes either facts or one ERROR fact), so a
    caller can always compute coverage as scopes_ok / scopes_total.
    """
    if base_session is None:
        import boto3
        base_session = boto3.Session()
    collectors = collectors or _collectors.COLLECTORS

    scopes = [(a, r) for a in accounts for r in regions]
    results = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(_collect_one_scope, base_session, a, role_name, r, collectors): (a, r)
            for (a, r) in scopes
        }
        for fut in cf.as_completed(futs):
            results.extend(fut.result())
    return results


def summarize(facts):
    """Aggregate stats over a multi-account fact list, for a run summary."""
    accounts = {f.get("account") for f in facts if f.get("account")}
    scopes = {(f.get("account"), f.get("region")) for f in facts}
    scope_errors = {(f["account"], f["region"]) for f in facts
                    if f.get("service") == "_scope" and f["status"] == "ERROR"}
    return {
        "accounts": len(accounts),
        "scopes": len(scopes),
        "scopes_failed_to_assume": len(scope_errors),
        "total_facts": len(facts),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Read-only multi-account, multi-region evidence collection.")
    ap.add_argument("--accounts", required=True,
                    help="comma-separated account IDs")
    ap.add_argument("--role-name", required=True,
                    help="read-only role to assume in each account (NOT admin)")
    ap.add_argument("--regions", default="us-east-1",
                    help="comma-separated regions (default us-east-1)")
    ap.add_argument("--profile", default=None,
                    help="base profile used to assume the per-account roles")
    ap.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    args = ap.parse_args()

    try:
        import boto3
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1

    accounts = [a.strip() for a in args.accounts.split(",") if a.strip()]
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    base = boto3.Session(profile_name=args.profile)

    facts = collect_across_accounts(accounts, args.role_name, regions,
                                    base_session=base, max_workers=args.max_workers)
    s = summarize(facts)
    print(f"accounts={s['accounts']} scopes={s['scopes']} "
          f"failed_assume={s['scopes_failed_to_assume']} facts={s['total_facts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
