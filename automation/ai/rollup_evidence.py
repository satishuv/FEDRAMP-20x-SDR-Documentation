"""AI evidence rollup (Layer 3, OPT-IN) -- summarizes, never claims.

Turns a KSI's collected posture facts into one readable "what the automation
observed this period" paragraph for the human-readable SDR. It summarizes
existing dated facts; it invents nothing and never upgrades an observation into
a compliance claim.

Advisory and read-only: it reads the facts store and prints (or, with --write,
records to a git-ignored AI sidecar keyed per KSI) a summary. It never writes
the record store, never sets a status, never writes assessment.

Opt-in; backend pluggable; offline TemplateRoller is the default (no model, no
network); BedrockRoller is opt-in via --roller bedrock.

Usage:
  python automation/ai/rollup_evidence.py            # print per-KSI summaries (offline)
  python automation/ai/rollup_evidence.py --write     # write the AI rollup sidecar
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
ROLLUP_SIDECAR = os.path.join(BASE, "sdr", "records", "evidence-rollup.ai-draft.json")


def load(path, default=None):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_all_facts_by_service():
    by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return by_service
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not (fn.startswith("facts-") and fn.endswith(".json")):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        for pf in store.get("posture_facts", []):
            by_service.setdefault(pf.get("service"), []).append(pf)
    return by_service


class TemplateRoller:
    """Offline deterministic summarizer. Stitches the facts into a paragraph
    without adding any judgment."""

    name = "template"

    def rollup(self, ksi_id, facts):
        if not facts:
            return None
        parts = [f"{f['service']}.{f['check']} was {f['status']} "
                 f"({f['detail']}) as of {f['collected_at']}" for f in facts[:8]]
        return (
            f"Automated observations for {ksi_id} this period: " + "; ".join(parts)
            + ". These are read-only telemetry observations, not a determination "
            "that the indicator is met; a human interprets them.")


class BedrockRoller:
    """OPT-IN LLM summarizer via Amazon Bedrock. Not wired by default. Summarizes
    only; adds no facts and no compliance conclusion."""

    name = "bedrock"

    def __init__(self, model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
                 region=None):
        import boto3
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def rollup(self, ksi_id, facts):
        import json as _json
        if not facts:
            return None
        listing = "; ".join(
            f"{f['service']}.{f['check']}={f['status']} ({f['detail']}) at {f['collected_at']}"
            for f in facts[:8])
        prompt = (
            "Summarize these dated AWS posture observations into one short, "
            "readable paragraph for a compliance reviewer. Summarize ONLY what "
            "is given; add no new facts and do NOT state the control is met. End "
            "by noting these are telemetry observations, not a determination.\n\n"
            f"KSI: {ksi_id}\nObservations: {listing}")
        body = _json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model_id, body=body)
        payload = _json.loads(resp["body"].read())
        return "".join(part.get("text", "") for part in payload.get("content", []))


def get_roller(name):
    if name == "bedrock":
        return BedrockRoller()
    return TemplateRoller()


def facts_for_ksi(ksi_entry, by_service, service_map):
    named = set(ksi_entry.get("services", []))
    out = []
    for svc_key, svc_label in service_map.items():
        if not any(svc_label in n for n in named):
            continue
        for pf in by_service.get(svc_key, []):
            if pf.get("status", "").startswith("ERROR"):
                continue
            out.append(pf)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI evidence rollup (summarizes existing facts; never claims).")
    ap.add_argument("--write", action="store_true",
                    help="write per-KSI summaries to the AI rollup sidecar")
    ap.add_argument("--roller", default="template", choices=["template", "bedrock"])
    args = ap.parse_args()

    registry = load(REGISTRY)
    if registry is None:
        print("Could not load the registry.")
        return 2
    by_service = load_all_facts_by_service()
    if not by_service:
        print("No facts found in automation/facts/. Run the collector first (read-only).")
        return 1

    try:
        roller = get_roller(args.roller)
    except Exception as e:  # noqa: BLE001
        print(f"Could not initialize roller '{args.roller}' ({type(e).__name__}); "
              "using the offline template roller.")
        roller = TemplateRoller()

    sys.path.insert(0, os.path.join(BASE, "automation", "prefill"))
    try:
        import prefill_from_facts as pf
        service_map = pf.POSTURE_SERVICE_KEYS
    except Exception:  # noqa: BLE001
        service_map = {}

    summaries = {}
    for kid, ksi_entry in registry.get("ksis", {}).items():
        facts = facts_for_ksi(ksi_entry, by_service, service_map)
        text = roller.rollup(kid, facts)
        if text:
            summaries[kid] = text

    if not summaries:
        print("No evidence to roll up (no facts matched any KSI's services).")
        return 0

    for kid, text in summaries.items():
        print(f"- {kid}: {text}\n")
    print(f"{len(summaries)} KSI evidence summaries (roller={roller.name}). "
          "Summaries of telemetry only; no status or assessment set.")

    if args.write:
        import json
        with open(ROLLUP_SIDECAR, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"roller": roller.name, "summaries": summaries}, f, indent=1)
        print(f"\nWrote {os.path.relpath(ROLLUP_SIDECAR, BASE)} (git-excluded).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
