"""AI pre-fill review / over-claim guard (Layer 3, OPT-IN) -- flags, never edits.

Reviews proposed draft prose (from the deterministic pre-fill sidecar or the AI
narrative-draft sidecar) against the backing facts, and flags any line whose
wording claims MORE than the observed facts support -- for example "fully
encrypted" or "all resources compliant" when the fact says "5 of 6" or "4
non-compliant". Over-claiming is the exact failure a compliance document must
avoid, so this is a safety net before a human applies a draft.

Advisory and read-only: it reads sidecars and facts and prints flags. It never
edits any draft, never writes the record store, never approves anything.

Opt-in; backend pluggable; the default TemplateReviewer is offline/deterministic
(pattern-based, no model, no network); BedrockReviewer is opt-in.

Usage:
  python automation/ai/review_overclaim.py            # flag over-claims in the sidecars (offline)
"""
import argparse
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FACTS_DIR = os.path.join(BASE, "automation", "facts")
SIDECARS = [
    os.path.join(BASE, "sdr", "records", "records-store.prefilled.json"),
    os.path.join(BASE, "sdr", "records", "records-store.ai-draft.json"),
]

# Absolute-claim wording that should be backed by a full/complete fact.
ABSOLUTE_TERMS = ("all ", "every ", "fully ", "always", "100%", "completely",
                  "no exceptions", "entirely")
# Signals in the backing facts that the state is PARTIAL (so an absolute claim
# is unsupported).
PARTIAL_SIGNALS = ("non-compliant", " of ", "stopped", "not enabled", "none",
                   "no coverage")


def load(path, default=None):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_facts_text():
    """All fact detail strings concatenated, lowercased, for cross-checking."""
    blob = []
    if os.path.isdir(FACTS_DIR):
        for fn in sorted(os.listdir(FACTS_DIR)):
            if fn.startswith("facts-") and fn.endswith(".json"):
                store = load(os.path.join(FACTS_DIR, fn), {})
                for pf in store.get("posture_facts", []):
                    blob.append(str(pf.get("detail", "")).lower())
    return " ".join(blob)


class TemplateReviewer:
    """Offline deterministic over-claim detector. Flags a draft line that uses
    absolute wording while the collected facts show a partial state."""

    name = "template"

    def flags(self, kid, field, text, facts_text):
        out = []
        low = text.lower()
        used_absolutes = [t for t in ABSOLUTE_TERMS if t in low]
        facts_show_partial = any(s in facts_text for s in PARTIAL_SIGNALS)
        if used_absolutes and facts_show_partial:
            out.append(
                f"{kid}.{field}: uses absolute wording ({', '.join(a.strip() for a in used_absolutes)}) "
                "while collected facts show a partial state (e.g. 'X of Y' or "
                "'non-compliant'). Confirm the claim is not stronger than the "
                "evidence before applying.")
        return out


class BedrockReviewer:
    """OPT-IN LLM reviewer via Amazon Bedrock. Not wired by default. Flags
    over-claims; never edits or approves."""

    name = "bedrock"

    def __init__(self, model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
                 region=None):
        import boto3
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def flags(self, kid, field, text, facts_text):
        import json as _json
        prompt = (
            "You are a compliance reviewer. Given a DRAFT narrative and the raw "
            "facts, flag ONLY where the draft claims more than the facts support "
            "(over-claiming). If it does not over-claim, reply exactly 'OK'. Do "
            "not rewrite; only flag.\n\n"
            f"Draft ({kid}.{field}): {text}\n\nFacts: {facts_text[:1500]}")
        body = _json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 200,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model_id, body=body)
        payload = _json.loads(resp["body"].read())
        text_out = "".join(p.get("text", "") for p in payload.get("content", [])).strip()
        return [] if text_out.upper() == "OK" else [f"{kid}.{field}: {text_out}"]


def get_reviewer(name):
    if name == "bedrock":
        return BedrockReviewer()
    return TemplateReviewer()


def iter_draft_lines(store):
    """Yield (kid, field, text) for the prose fields worth reviewing."""
    for kid, rec in store.get("ksi", {}).items():
        for field in ("implementation", "validation"):
            val = rec.get(field)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        yield kid, field, item
            elif isinstance(val, str):
                yield kid, field, val


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI over-claim guard (flags only; never edits or approves).")
    ap.add_argument("--reviewer", default="template", choices=["template", "bedrock"])
    args = ap.parse_args()

    facts_text = load_facts_text()
    try:
        reviewer = get_reviewer(args.reviewer)
    except Exception as e:  # noqa: BLE001
        print(f"Could not initialize reviewer '{args.reviewer}' ({type(e).__name__}); "
              "using the offline template reviewer.")
        reviewer = TemplateReviewer()

    reviewed = 0
    all_flags = []
    for sidecar in SIDECARS:
        store = load(sidecar)
        if store is None:
            continue
        for kid, field, text in iter_draft_lines(store):
            reviewed += 1
            all_flags.extend(reviewer.flags(kid, field, text, facts_text))

    if reviewed == 0:
        print("No draft sidecars found to review. Run the pre-fill or the AI "
              "narrative drafter first; this guard reviews their proposed prose.")
        return 0

    if not all_flags:
        print(f"Reviewed {reviewed} draft line(s) (reviewer={reviewer.name}). "
              "No over-claims flagged.")
        return 0

    print(f"Reviewed {reviewed} draft line(s) (reviewer={reviewer.name}); "
          f"{len(all_flags)} potential over-claim(s) to check:\n")
    for flag in all_flags:
        print("- " + flag)
    print("\nAdvisory only. Nothing was edited or approved; a human resolves "
          "each flag before applying the draft.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
