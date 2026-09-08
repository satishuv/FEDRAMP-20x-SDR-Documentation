# Build the collector registry: a machine-readable map from each Key
# Security Indicator (KSI) to concrete read-only AWS checks, derived from
# traceability/aws-service-ksi-map.json.
#
# Layer 1 of the automation design: deterministic collectors only. Each
# check is one of:
#   config_managed_rule  - an AWS Config managed rule named in the guidance
#                          (backtick-quoted); collectable today via
#                          config:DescribeComplianceByConfigRule.
#   described_method     - a verify or validate method described in prose;
#                          carried for traceability until a dedicated
#                          collector implements it.
# Pipeline position: run after build_notes.py (needs the service map).
# Deterministic: output is pinned to the dataset version, no run timestamps.

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVICE_MAP = os.path.join(BASE, "traceability", "aws-service-ksi-map.json")
OUT_DIR = os.path.join(BASE, "automation", "collectors")
OUT = os.path.join(OUT_DIR, "registry.json")
# Stage 1 triage: which pending KSIs now have a real read-only collector
# (bucket_a) versus a provider-deployed Config custom rule (bucket_b). The
# registry reads this so the collectable-now count regenerates deterministically
# instead of being hand-edited.
CLASSIFICATION = os.path.join(OUT_DIR, "pending-ksi-classification.json")

# Service names recognized in guidance prose, longest match first.
SERVICES = [
    "AWS IAM Identity Center", "AWS Identity and Access Management Access Analyzer",
    "IAM Access Analyzer", "AWS Security Hub", "AWS CloudTrail", "Amazon CloudWatch",
    "Amazon EventBridge", "AWS Config", "AWS Lambda", "Amazon Inspector",
    "AWS Key Management Service", "AWS KMS", "AWS Backup", "Amazon GuardDuty",
    "AWS Organizations", "AWS Systems Manager", "Amazon S3", "AWS CodePipeline",
    "AWS CodeBuild", "AWS CloudFormation", "AWS Secrets Manager",
    "AWS Certificate Manager", "Amazon Macie", "AWS WAF", "AWS Shield",
    "Amazon Detective", "AWS Audit Manager", "AWS Artifact", "Amazon VPC",
    "AWS Network Firewall", "Amazon Route 53", "AWS Firewall Manager",
    "Amazon ECR", "Amazon EC2", "AWS Step Functions", "Amazon SNS",
    "Amazon Athena", "AWS Glue", "Amazon QuickSight", "AWS Control Tower",
    "Amazon Security Lake", "AWS Resource Explorer", "IAM",
]

RULE_PAT = re.compile(r"`([a-z0-9][a-z0-9-]*)`")


def find_services(text):
    found = []
    for s in SERVICES:
        if s in text and s not in found:
            # skip bare IAM if a more specific IAM service already matched
            if s == "IAM" and any("IAM" in f or "Identity" in f for f in found):
                continue
            found.append(s)
    return found


def main():
    smap = json.load(open(SERVICE_MAP, encoding="utf-8"))
    # Load the Stage 1 triage. bucket_a KSIs now have a real read-only
    # collector, so their described-method checks are collectable now.
    # bucket_b KSIs are provider-deployed Config custom rules, not repo
    # collectors, so they stay not-collectable and are flagged provider_deployed.
    bucket_a, bucket_b = set(), set()
    if os.path.exists(CLASSIFICATION):
        cls = json.load(open(CLASSIFICATION, encoding="utf-8"))
        bucket_a = set(cls.get("bucket_a", {}).get("ksis", {}).keys())
        bucket_b = set(cls.get("bucket_b", {}).get("ksis", {}).keys())
    registry = {}
    total_rules = 0
    for kid, e in sorted(smap["ksis"].items()):
        checks = []
        for source in ("verify", "validate"):
            text = e[f"{source}_method"]
            rules = RULE_PAT.findall(text)
            for rule in rules:
                checks.append({
                    "check_id": f"{kid}:{source}:config:{rule}",
                    "type": "config_managed_rule",
                    "service": "AWS Config",
                    "target": rule,
                    "source": source,
                    "collectable_now": True,
                })
            total_rules += len(rules)
            # A described method becomes collectable now when a read-only
            # collector was built for this KSI (bucket_a). Bucket_b keeps it
            # false and records that it is provider-deployed infrastructure.
            method_check = {
                "check_id": f"{kid}:{source}:method",
                "type": "described_method",
                "services": find_services(text),
                "description": text,
                "source": source,
                "collectable_now": kid in bucket_a,
            }
            if kid in bucket_a:
                method_check["collector"] = "automation/collectors/collectors.py"
            if kid in bucket_b:
                method_check["provider_deployed"] = True
                method_check["deploy"] = "automation/config-rules/ (Config custom rule)"
            checks.append(method_check)
        registry[kid] = {
            "name": e["name"],
            "family": e["family"],
            "family_name": e["family_name"],
            "services": find_services(
                e["aws_implementation"] + " " + e["verify_method"] + " "
                + e["validate_method"]),
            "checks": checks,
        }
    doc = {
        "meta": {
            "title": "KSI collector registry (Layer 1: deterministic read-only checks)",
            "derived_from": "traceability/aws-service-ksi-map.json",
            "dataset_version": smap["meta"]["dataset_version"],
            "ksis": len(registry),
            "config_managed_rule_checks": total_rules,
            "boundary": (
                "Collectors are read-only by design and produce facts, "
                "never statuses. A status changes only through deterministic "
                "checks plus human sign-off; generative output is never "
                "deterministic telemetry (FedRAMP definitions)."
            ),
        },
        "ksis": registry,
    }
    collectable = sum(1 for k in registry.values()
                      for c in k["checks"] if c["collectable_now"])
    ksis_collectable = sum(
        1 for k in registry.values()
        if any(c["collectable_now"] for c in k["checks"]))
    ksis_provider_deployed = sum(
        1 for k in registry.values()
        if any(c.get("provider_deployed") for c in k["checks"]))
    doc["meta"]["ksis_collectable_now"] = ksis_collectable
    doc["meta"]["ksis_provider_deployed_only"] = ksis_provider_deployed
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
    print(f"registry: {len(registry)} KSIs, {ksis_collectable} collectable now "
          f"(KSI level), {ksis_provider_deployed} provider-deployed only, "
          f"{collectable} collectable checks, "
          f"{sum(len(k['checks']) for k in registry.values())} checks total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
