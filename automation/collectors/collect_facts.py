# Layer 1 facts collector: execute the collectable checks in registry.json
# against an AWS account, read-only, and write a timestamped facts store.
#
# Read-only by construction: the only AWS calls made are
# config:DescribeComplianceByConfigRule and sts:GetCallerIdentity. Run with
# ReadOnly or least-privilege credentials; never with admin credentials.
#
# Facts are telemetry, not statuses. This script never writes to the record
# store and never marks anything Implemented; it produces evidence for a
# human (or a gated pipeline step) to act on. The facts store carries real
# run timestamps because it is telemetry; it is excluded from git.
#
# Usage: python automation/collectors/collect_facts.py [--profile NAME] [--region REGION]

import argparse
import json
import os
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None, help="AWS profile (use a ReadOnly one)")
    ap.add_argument("--region", default=None, help="AWS region (defaults to profile/env region)")
    args = ap.parse_args()

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1

    registry = json.load(open(REGISTRY, encoding="utf-8"))
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ident = session.client("sts").get_caller_identity()
    except (botocore.exceptions.ProfileNotFound,
            botocore.exceptions.NoCredentialsError,
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError) as e:
        print(f"No usable AWS credentials ({type(e).__name__}); nothing collected. "
              "Configure a ReadOnly profile and re-run.")
        return 1
    arn = ident.get("Arn", "")
    if "admin" in arn.lower():
        print(f"Refusing to run with an admin-looking identity: {arn}. "
              "Use ReadOnly or least-privilege credentials.")
        return 1

    config = session.client("config")
    region = session.region_name or "unknown-region"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Gather the unique Config managed rule names across all KSIs.
    rule_to_checks = {}
    for kid, entry in registry["ksis"].items():
        for check in entry["checks"]:
            if check.get("collectable_now") and check["type"] == "config_managed_rule":
                rule_to_checks.setdefault(check["target"], []).append(check["check_id"])

    facts = []
    for rule, check_ids in sorted(rule_to_checks.items()):
        fact = {"rule": rule, "check_ids": check_ids, "collected_at": now,
                "region": region}
        try:
            resp = config.describe_compliance_by_config_rule(ConfigRuleNames=[rule])
            results = resp.get("ComplianceByConfigRules", [])
            if results:
                comp = results[0].get("Compliance", {})
                fact["compliance_type"] = comp.get("ComplianceType", "UNKNOWN")
            else:
                fact["compliance_type"] = "RULE_NOT_DEPLOYED"
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            fact["compliance_type"] = ("RULE_NOT_DEPLOYED"
                                       if code == "NoSuchConfigRuleException" else f"ERROR:{code}")
        facts.append(fact)
        print(f"  {rule}: {fact['compliance_type']}")

    os.makedirs(FACTS_DIR, exist_ok=True)
    out = os.path.join(FACTS_DIR, f"facts-{region}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "meta": {
                "collected_at": now,
                "region": region,
                "identity_arn": arn,
                "registry_dataset_version": registry["meta"]["dataset_version"],
                "note": ("Facts are read-only telemetry, not statuses. "
                         "Never commit this file; it may identify a real account."),
            },
            "facts": facts,
        }, f, indent=1)
    deployed = sum(1 for x in facts if x["compliance_type"] in ("COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA"))
    print(f"wrote {out}: {len(facts)} rules checked, {deployed} deployed in this account/region")
    return 0


if __name__ == "__main__":
    sys.exit(main())
