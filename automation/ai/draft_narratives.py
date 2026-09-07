"""AI narrative drafting (Layer 3, OPT-IN) -- assists, never decides.

Drafts a first-pass `implementation` / `validation` narrative for each KSI from
the collected facts plus the KSI's official guidance, so authoring 46 KSIs
becomes a review task. This module is OPTIONAL: the deterministic pipeline
(collect -> pre-fill -> build -> validate) runs identically whether this module
is present, enabled, or absent.

The hard boundary, enforced here in code (mirrors prefill_from_facts.py):
  - Never sets or changes `implementation_status` (human judgment + sign-off).
  - Never writes `assessment` (accredited independent assessor only).
  - Never writes `tests` or `evidence` (those are deterministic telemetry from
    the collectors, not AI-authored).
  - Never edits the record store in place. It writes a proposed copy to a
    SEPARATE AI-draft sidecar and prints a unified diff. A human reviews,
    edits, and applies by hand.
  - Only drafts into fields that are still TBD/empty. Author-written prose is
    never overwritten.

Backend is pluggable and there is NO default network call. The default drafter
is a deterministic, offline TEMPLATE drafter (no model, no network) so this
module and its tests run with zero AI backend. A provider who wants real LLM
drafting supplies a drafter (e.g. Amazon Bedrock) explicitly; nothing here is
wired to an endpoint, and no data leaves the provider's boundary by default.

Usage:
  python automation/ai/draft_narratives.py            # print the diff (stub drafter)
  python automation/ai/draft_narratives.py --write     # write the AI sidecar
  # A real backend is opt-in via --drafter bedrock (requires the provider to
  # have configured Bedrock access); absent that, the offline stub is used.
"""
import argparse
import copy
import difflib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
RECORD_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
# Distinct sidecar name so an AI draft is never confused with the deterministic
# pre-fill sidecar or the real record store. Git-ignored like other sidecars.
AI_SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.ai-draft.json")

TBD_MARKERS = ("TBD:", "TBD ", "Information has not been provided", "FedRAMP pending")

# Fields this module may DRAFT into. Deliberately excludes implementation_status,
# assessment, tests, and evidence. Guarded again at write time.
DRAFTABLE_FIELDS = ("implementation", "validation")
FORBIDDEN_FIELDS = ("implementation_status", "assessment", "tests", "evidence")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def is_tbd(value):
    if isinstance(value, str):
        return any(m in value for m in TBD_MARKERS) or value.strip() == ""
    if isinstance(value, list):
        return len(value) == 0 or all(is_tbd(v) for v in value)
    return False


def load_all_posture_facts():
    """Merge posture facts from every facts-*.json, keyed by service. Read-only."""
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


# ---- Pluggable drafter interface -------------------------------------------
#
# A drafter takes (ksi_id, ksi_guidance, facts) and returns a short prose draft
# string, or None to decline. It MUST NOT perform any AWS calls or make a
# compliance claim; it drafts descriptive prose for a human to verify.

class TemplateDrafter:
    """Default offline drafter: deterministic, no model, no network. Produces a
    plainly-labeled DRAFT that stitches the KSI guidance and the observed facts
    into review-ready prose. It never asserts the control is met."""

    name = "template"

    def draft(self, kind, ksi_id, guidance, facts):
        looks = guidance.get("what_it_looks_for") or guidance.get("aws_implementation") or ""
        observed = "; ".join(
            f"{f['service']}.{f['check']}={f['status']} ({f['detail']})"
            for f in facts[:6]
        ) or "no automated facts collected for this indicator yet"
        verb = "implements" if kind == "implementation" else "validates"

        def _clip(s, n):
            s = s.strip()
            return s if len(s) <= n else s[:s.rfind(" ", 0, n)].rstrip() + "..."

        return (
            f"DRAFT (AI-assisted, unverified -- review before use): This is a "
            f"proposed {kind} narrative for {ksi_id}, to be confirmed and edited "
            f"by the provider. Intended measure: {_clip(looks, 280)} "
            f"Observed automated posture that may support how the offering {verb} "
            f"this: {_clip(observed, 280)}. A passing observation is telemetry, "
            f"not a compliance conclusion; the provider must confirm accuracy and "
            f"completeness before relying on this text."
        )


class BedrockDrafter:
    """OPT-IN real LLM drafter via Amazon Bedrock. Not wired by default; the
    provider must have Bedrock access configured. Kept minimal and clearly
    isolated: it only drafts prose and cannot touch AWS posture or the record
    store. If boto3/Bedrock is unavailable, construction fails loudly so the
    caller falls back to the offline stub rather than silently degrading."""

    name = "bedrock"

    def __init__(self, model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
                 region=None):
        import boto3  # opt-in dependency; only imported if this drafter is chosen
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def draft(self, kind, ksi_id, guidance, facts):
        import json as _json
        looks = guidance.get("what_it_looks_for") or guidance.get("aws_implementation") or ""
        observed = "; ".join(
            f"{f['service']}.{f['check']}={f['status']} ({f['detail']})"
            for f in facts[:6]
        )
        prompt = (
            "You are drafting a FedRAMP SDR narrative for a human to review and "
            "edit. Draft ONLY a descriptive " + kind + " narrative. Do NOT claim "
            "the control is met, do NOT assign a status, do NOT invent facts "
            "beyond those given. Prefix the output with 'DRAFT (AI-assisted, "
            "unverified):'.\n\n"
            f"KSI: {ksi_id}\nIntended measure: {looks}\n"
            f"Observed automated posture: {observed or 'none collected'}\n"
        )
        body = _json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 400,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model_id, body=body)
        payload = _json.loads(resp["body"].read())
        text = "".join(part.get("text", "") for part in payload.get("content", []))
        # Defensive: ensure the draft label is present even if the model omits it.
        if "DRAFT" not in text:
            text = "DRAFT (AI-assisted, unverified -- review before use): " + text
        return text


def get_drafter(name):
    if name == "bedrock":
        return BedrockDrafter()
    return TemplateDrafter()


# ---- Drafting (never touches status/assessment/tests/evidence) --------------

def posture_facts_for_ksi(ksi_entry, posture_by_service, service_map):
    named = set(ksi_entry.get("services", []))
    out = []
    for svc_key, svc_label in service_map.items():
        if not any(svc_label in n for n in named):
            continue
        for pf in posture_by_service.get(svc_key, []):
            status = pf.get("status", "")
            if status.startswith("ERROR") or status in (
                    "NONE", "NO_COVERAGE", "NOT_ENABLED", "NO_KEYS"):
                continue
            out.append(pf)
    return out


def draft_ksi(kid, record, ksi_entry, posture_by_service, drafter, service_map):
    """Draft implementation/validation prose into TBD fields only. Returns
    (changed, notes). Mutates the record on the proposed copy only."""
    facts = posture_facts_for_ksi(ksi_entry, posture_by_service, service_map)
    guidance = ksi_entry.get("fill_guidance", {}) or ksi_entry
    notes = []
    changed = False
    for field in DRAFTABLE_FIELDS:
        if not is_tbd(record.get(field, "")):
            continue  # never overwrite author-written prose
        text = drafter.draft(field, kid, guidance, facts)
        if text:
            record[field] = [text] if isinstance(record.get(field), list) else text
            changed = True
            notes.append(f"{kid}: drafted {field} ({drafter.name})")
    return changed, notes


def _assert_boundary(before_record, after_record, kid):
    """Hard guard: the forbidden fields must be byte-identical before/after."""
    for field in FORBIDDEN_FIELDS:
        if before_record.get(field) != after_record.get(field):
            raise AssertionError(
                f"BOUNDARY VIOLATION on {kid}: AI drafting changed '{field}', "
                "which it must never touch. Aborting.")


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI narrative drafting (reviewable diff; assists, never decides).")
    ap.add_argument("--write", action="store_true",
                    help="write the proposed AI-draft sidecar file")
    ap.add_argument("--drafter", default="template", choices=["template", "bedrock"],
                    help="drafting backend; 'template' is offline/default, "
                         "'bedrock' is opt-in and requires provider Bedrock access")
    args = ap.parse_args()

    registry = load(REGISTRY)
    store = load(RECORD_STORE)
    if registry is None or store is None:
        print("Could not load the registry or the record store.")
        return 2

    posture_by_service = load_all_posture_facts()
    if not posture_by_service:
        print("No facts found in automation/facts/. Run the collector first "
              "(read-only): python automation/collectors/collect_facts.py --profile <ReadOnly>")
        return 1

    try:
        drafter = get_drafter(args.drafter)
    except Exception as e:  # noqa: BLE001 - a missing backend must fall back cleanly
        print(f"Could not initialize drafter '{args.drafter}' ({type(e).__name__}); "
              "falling back to the offline template drafter.")
        drafter = TemplateDrafter()

    # Import the deterministic prefill's service map so AI and prefill agree on
    # which service informs which KSI. Kept as the single source of truth.
    sys.path.insert(0, os.path.join(BASE, "automation", "prefill"))
    try:
        import prefill_from_facts as pf
        service_map = pf.POSTURE_SERVICE_KEYS
    except Exception:  # noqa: BLE001
        service_map = {}

    proposed = copy.deepcopy(store)
    ksi_records = proposed.get("ksi", {})
    all_notes = []
    drafted = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        record = ksi_records.get(kid)
        if record is None:
            continue
        before = copy.deepcopy(record)
        changed, notes = draft_ksi(kid, record, ksi_entry, posture_by_service,
                                   drafter, service_map)
        _assert_boundary(before, record, kid)  # enforce the boundary per KSI
        if changed:
            drafted += 1
        all_notes.extend(notes)

    if drafted == 0:
        print("No KSI narratives were drafted (fields already authored, or no "
              "matching facts). AI drafting only fills TBD implementation/"
              "validation prose.")
        return 0

    before = json.dumps(store, indent=1, ensure_ascii=False).splitlines(keepends=True)
    after = json.dumps(proposed, indent=1, ensure_ascii=False).splitlines(keepends=True)
    sys.stdout.writelines(difflib.unified_diff(
        before, after,
        fromfile="records-store.json (current)",
        tofile="records-store.json (proposed AI draft)"))

    print(f"\nAI draft summary (drafter={drafter.name}):")
    for note in all_notes:
        print(f"  {note}")
    print(f"\n{drafted} KSI(s) received a DRAFT implementation/validation narrative.")
    print("This is an AI-ASSISTED PROPOSAL. implementation_status, assessment, "
          "tests, and evidence were NOT touched. Every draft is unverified; a "
          "human must confirm accuracy before use.")

    if args.write:
        with open(AI_SIDECAR, "w", encoding="utf-8", newline="\n") as f:
            json.dump(proposed, f, indent=1)
        print(f"\nWrote AI draft to {os.path.relpath(AI_SIDECAR, BASE)} "
              "(git-excluded). Diff it against the real store and apply what is "
              "correct by hand.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
