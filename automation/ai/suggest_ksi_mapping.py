"""AI architecture-to-KSI suggester (Layer 3, OPT-IN) -- suggests, never decides.

Given a provider's list of AWS services (their architecture), suggests which
KSIs each service most directly supports and what evidence to collect, to speed
onboarding of a new authorization boundary. Suggestions must be confirmed by a
human against the canonical CR26 dataset; they are a starting point, never
authoritative.

Advisory and read-only: it reads the repo's own KSI-to-service map
(traceability/aws-service-ksi-map.json) and prints suggestions. It writes
nothing, sets no status, makes no compliance claim.

The default mapper is deterministic and offline (it matches service names to the
map the repo already ships). A Bedrock mapper is opt-in for free-text stack
descriptions; absent it, pass explicit service names.

Usage:
  python automation/ai/suggest_ksi_mapping.py --services "AWS Config,Amazon S3,AWS CloudTrail"
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KSI_MAP = os.path.join(BASE, "traceability", "aws-service-ksi-map.json")


def load(path, default=None):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def suggest_from_services(services, ksi_map):
    """Deterministic: for each KSI, if any of the provider's named services
    appears in the KSI's aws_implementation text, suggest that KSI. Returns
    {service: [ksi_ids]} and a coverage note. Read-only, no model needed."""
    ksis = ksi_map.get("ksis", {})
    by_service = {s: [] for s in services}
    for kid, entry in ksis.items():
        blob = " ".join([
            entry.get("aws_implementation", ""),
            entry.get("verify_method", ""),
            entry.get("validate_method", ""),
        ]).lower()
        for s in services:
            if s.lower() in blob:
                by_service[s].append(kid)
    return by_service


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI architecture-to-KSI suggester (advisory; confirm against canonical dataset).")
    ap.add_argument("--services", required=True,
                    help="comma-separated AWS service names as they appear in guidance, "
                         "e.g. 'AWS Config,Amazon S3,AWS CloudTrail'")
    args = ap.parse_args()

    ksi_map = load(KSI_MAP)
    if ksi_map is None:
        print(f"Could not load {os.path.relpath(KSI_MAP, BASE)}.")
        return 2

    services = [s.strip() for s in args.services.split(",") if s.strip()]
    if not services:
        print("No services provided. Pass --services 'AWS Config,Amazon S3,...'.")
        return 1

    suggestions = suggest_from_services(services, ksi_map)
    total = ksi_map.get("meta", {}).get("count", len(ksi_map.get("ksis", {})))

    print(f"Suggested KSI coverage for the named services (advisory; {total} KSIs total):\n")
    for svc, kids in suggestions.items():
        if kids:
            print(f"- {svc}: may support {len(kids)} KSI(s): {', '.join(sorted(kids))}")
        else:
            print(f"- {svc}: no direct KSI match in the guidance map "
                  "(may still be supporting infrastructure)")
    print("\nThese are SUGGESTIONS derived from reference-architecture guidance, "
          "not a compliance determination. Confirm each mapping against the "
          "canonical CR26 dataset and your real implementation before relying "
          "on it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
