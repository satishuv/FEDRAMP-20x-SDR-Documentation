"""AI finding explainer (Layer 3, OPT-IN) -- advisory only, no write path.

Turns raw collected facts (for example "config.rule_compliance = 3 compliant,
4 non-compliant of 25") into a plain-English explanation for the engineer:
what the finding means, why it matters, and a suggested remediation direction.

This is the most tightly-bounded AI module in the pipeline: it has NO write
path at all. It reads the facts store (read-only) and prints explanations. It
does not write the record store, does not write any sidecar, does not set a
status, does not conclude compliance. It is a reading aid, nothing more.

Opt-in by construction: the deterministic pipeline runs identically without
this module. Backend is pluggable with NO default network call, the default
TemplateExplainer is offline/deterministic (no model), and a BedrockExplainer
is opt-in via --explainer bedrock (imports boto3 only if chosen).

Usage:
  python automation/ai/explain_findings.py                 # explain notable facts (offline)
  python automation/ai/explain_findings.py --explainer bedrock   # opt-in LLM
  python automation/ai/explain_findings.py --all           # explain every fact, not just notable ones
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FACTS_DIR = os.path.join(BASE, "automation", "facts")

# A fact is "notable" (worth explaining) if its status signals a gap or a
# partial state a human should look at, rather than a clean pass.
NOTABLE_STATUS_MARKERS = ("NON_COMPLIANT", "STOPPED", "NONE", "NOT_ENABLED",
                          "NO_COVERAGE", "NO_KEYS", "ERROR")
# Some OBSERVED facts carry a partial count worth surfacing (e.g. "5 of 6").
NOTABLE_DETAIL_MARKERS = ("non-compliant", "of ", "STOPPED", "not ")


def load(path, default=None):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_all_facts():
    facts = []
    if not os.path.isdir(FACTS_DIR):
        return facts
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not (fn.startswith("facts-") and fn.endswith(".json")):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        facts.extend(store.get("posture_facts", []))
    return facts


def is_notable(fact):
    status = fact.get("status", "")
    detail = fact.get("detail", "")
    if any(m in status for m in NOTABLE_STATUS_MARKERS):
        return True
    # A partial "X of Y" where X < Y is notable.
    return "non-compliant" in detail.lower()


# ---- Pluggable explainer interface -----------------------------------------
#
# An explainer takes a fact and returns a plain-English explanation string. It
# MUST be advisory only: it explains and suggests, it never concludes that a
# control is met or not met, and it has no way to write anything.

# Static, curated guidance per service/check. Deterministic, offline, and
# reviewable. The LLM explainer can produce richer text, but this is the safe
# default and needs no backend.
_GUIDANCE = {
    ("config", "rule_compliance"):
        ("AWS Config evaluates your resources against rules. Non-compliant "
         "rules mean some resources deviate from the configured baseline. "
         "Review each non-compliant rule in the Config console to see which "
         "resources and why, then remediate the resource or adjust the rule if "
         "the baseline is wrong."),
    ("config", "recorder"):
        ("The AWS Config recorder captures resource configuration over time. If "
         "it is STOPPED or missing, you lose configuration history and most "
         "verify-layer evidence. Turn recording on for all supported resource "
         "types in every in-scope region and account."),
    ("kms", "key_rotation"):
        ("Automatic key rotation periodically rotates KMS key material. Keys "
         "without rotation should be reviewed: enable automatic rotation where "
         "appropriate, or document why a specific key is exempt."),
    ("iam", "password_policy"):
        ("No account password policy means residual local credentials are "
         "unconstrained. Set an IAM account password policy (length, "
         "complexity, reuse, expiry) even if human access is federated."),
    ("cloudtrail", "trails"):
        ("CloudTrail records API activity. Confirm a multi-region trail exists "
         "and is actively logging with log-file validation, so audit evidence "
         "is complete and tamper-evident."),
    ("s3", "public_access_block"):
        ("S3 public access block prevents buckets from becoming public. Any "
         "bucket not fully blocking public access should be reviewed and, "
         "unless intentionally public, have all four block settings enabled."),
    ("guardduty", "detector"):
        ("GuardDuty is threat detection. If no detector is enabled in a region, "
         "that region has no runtime threat monitoring; enable it everywhere "
         "in scope."),
    ("securityhub", "enabled"):
        ("Security Hub aggregates findings and scores against standards. If it "
         "is not enabled, you lose the central findings view; enable it and the "
         "relevant security standards across accounts."),
}


class TemplateExplainer:
    """Default offline explainer: deterministic, curated guidance. No model,
    no network. Advisory only."""

    name = "template"

    def explain(self, fact):
        key = (fact.get("service"), fact.get("check"))
        base = _GUIDANCE.get(key, (
            "Review this observation in the service console to determine "
            "whether it meets your intended control, and remediate if not."))
        return (
            f"[{fact.get('service')}.{fact.get('check')} = {fact.get('status')}] "
            f"Observed: {fact.get('detail')} (region {fact.get('region')}). "
            f"What this means and what to check: {base} "
            "This is advisory guidance from telemetry, not a compliance "
            "determination; a human decides whether the control is met.")


class BedrockExplainer:
    """OPT-IN LLM explainer via Amazon Bedrock. Not wired by default. Advisory
    only: it explains a fact and suggests remediation; it cannot conclude
    compliance and has no write path."""

    name = "bedrock"

    def __init__(self, model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
                 region=None):
        import boto3
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def explain(self, fact):
        import json as _json
        prompt = (
            "Explain this AWS security-posture observation to an engineer in "
            "plain English: what it means, why it matters, and a suggested "
            "remediation direction. Be advisory only, do NOT conclude the "
            "control is met or not met, and do NOT invent facts. End by noting "
            "this is telemetry, not a compliance determination.\n\n"
            f"Observation: {fact.get('service')}.{fact.get('check')} = "
            f"{fact.get('status')} -- {fact.get('detail')} "
            f"(region {fact.get('region')})"
        )
        body = _json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 350,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model_id, body=body)
        payload = _json.loads(resp["body"].read())
        return "".join(part.get("text", "") for part in payload.get("content", []))


def get_explainer(name):
    if name == "bedrock":
        return BedrockExplainer()
    return TemplateExplainer()


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI finding explainer (advisory, read-only, no write path).")
    ap.add_argument("--all", action="store_true",
                    help="explain every fact, not just notable ones")
    ap.add_argument("--explainer", default="template", choices=["template", "bedrock"],
                    help="backend; 'template' is offline/default, 'bedrock' is opt-in")
    args = ap.parse_args()

    facts = load_all_facts()
    if not facts:
        print("No facts found in automation/facts/. Run the collector first "
              "(read-only): python automation/collectors/collect_facts.py --profile <ReadOnly>")
        return 1

    try:
        explainer = get_explainer(args.explainer)
    except Exception as e:  # noqa: BLE001 - missing backend falls back cleanly
        print(f"Could not initialize explainer '{args.explainer}' "
              f"({type(e).__name__}); using the offline template explainer.")
        explainer = TemplateExplainer()

    selected = facts if args.all else [f for f in facts if is_notable(f)]
    if not selected:
        print("No notable findings to explain (nothing flagged). "
              "Use --all to explain every collected fact.")
        return 0

    print(f"AI finding explanations (explainer={explainer.name}, "
          f"{len(selected)} of {len(facts)} facts):\n")
    for f in selected:
        print("- " + explainer.explain(f) + "\n")
    print("Advisory only. Nothing above sets a status or writes any file; a "
          "human decides remediation and compliance.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
