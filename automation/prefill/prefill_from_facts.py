# Deterministic fact-to-field pre-fill (Layer 2 core, no LLM).
#
# Reads a collected facts store and the collector registry, and proposes
# additions to each KSI's `tests`, `evidence`, and `extension`.
# `automation_verification` field, every proposed line carrying provenance back
# to the dated collector fact that justifies it. This turns the authoring task
# (writing 46 KSIs from a blank template) into a review task.
#
# The hard boundary, enforced here in code:
#   - Never sets or changes `implementation_status`. A status is a human
#     judgment plus sign-off; a passing telemetry fact is not that.
#   - Never writes `assessment` (accredited independent assessor only).
#   - Never edits the record store in place. It writes a proposed copy to a
#     sidecar file and prints a unified diff. A human reviews and applies.
#   - Only proposes for facts that are dated and not ERROR/None. A missing or
#     failed fact leaves the field as the provider must author it.
#
# Usage:
#   python automation/prefill/prefill_from_facts.py            # print the diff
#   python automation/prefill/prefill_from_facts.py --write    # write sidecar
#
# The sidecar (records-store.prefilled.json) is git-excluded like the facts
# store; the provider diffs it, keeps the lines that are right, and edits the
# real record store by hand. Nothing here decides compliance.

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
SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.prefilled.json")

TBD_MARKERS = ("TBD:", "TBD ", "Information has not been provided")

# Map a collector posture service to the KSI families it most directly informs.
# Used only to attach a posture fact to the right KSIs when the registry's
# per-KSI service list names that service. This is a hint for provenance, not
# a compliance decision.
POSTURE_SERVICE_KEYS = {
    "security_hub": "AWS Security Hub",
    "access_analyzer": "Access Analyzer",
    "inspector": "Amazon Inspector",
    "guardduty": "Amazon GuardDuty",
    "backup": "AWS Backup",
    "kms": "AWS Key Management Service",
    "config": "AWS Config",
    "cloudtrail": "AWS CloudTrail",
    "s3": "Amazon S3",
    "iam": "IAM",
}


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


def load_all_facts():
    """Merge every facts-*.json in the facts store into one view keyed by the
    collector check_id (config rules) and by service (posture facts)."""
    config_by_rule = {}
    posture_by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return config_by_rule, posture_by_service, None
    latest_ts = None
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not fn.startswith("facts-") or not fn.endswith(".json"):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        latest_ts = store.get("meta", {}).get("collected_at") or latest_ts
        for fact in store.get("facts", []):
            config_by_rule[fact.get("rule")] = fact
        for pf in store.get("posture_facts", []):
            posture_by_service.setdefault(pf.get("service"), []).append(pf)
    return config_by_rule, posture_by_service, latest_ts


def config_facts_for_ksi(ksi_entry, config_by_rule):
    """Dated Config-rule facts that back this KSI, from the registry checks."""
    out = []
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        fact = config_by_rule.get(check.get("target"))
        if not fact:
            continue
        ct = fact.get("compliance_type", "")
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        out.append((check, fact))
    return out


def posture_facts_for_ksi(ksi_entry, posture_by_service):
    """Posture facts whose service is named in this KSI's registry service
    list. Skips ERROR/None-status facts so only real observations pre-fill."""
    named = set(ksi_entry.get("services", []))
    out = []
    for svc_key, svc_label in POSTURE_SERVICE_KEYS.items():
        if not any(svc_label in n for n in named):
            continue
        for pf in posture_by_service.get(svc_key, []):
            status = pf.get("status", "")
            if status.startswith("ERROR") or status in ("NONE", "NO_COVERAGE",
                                                         "NOT_ENABLED", "NO_KEYS"):
                continue
            out.append(pf)
    return out


def prefill_ksi(kid, record, ksi_entry, config_by_rule, posture_by_service):
    """Return (changed, notes). Mutates `record` in place on the proposed copy.
    Only fills fields that are still in TBD/empty template state."""
    notes = []
    cfg = config_facts_for_ksi(ksi_entry, config_by_rule)
    posture = posture_facts_for_ksi(ksi_entry, posture_by_service)
    if not cfg and not posture:
        return False, notes

    changed = False

    # tests: append a dated automated-method line per backing fact, only if the
    # tests list is still empty/template.
    if is_tbd(record.get("tests", [])):
        new_tests = []
        for check, fact in cfg:
            new_tests.append(
                f"Automated (collector): AWS Config rule `{check['target']}` "
                f"reported {fact['compliance_type']} on {fact['collected_at']} "
                f"({check['source']} method). Provenance: {check['check_id']}.")
        for pf in posture:
            new_tests.append(
                f"Automated (collector): {pf['service']}.{pf['check']} = "
                f"{pf['status']} on {pf['collected_at']}. {pf['detail']}.")
        if new_tests:
            record["tests"] = new_tests
            changed = True
            notes.append(f"{kid}: filled {len(new_tests)} test line(s) from facts")

    # evidence: append schema-valid evidence OBJECTS, only if still empty. The
    # official SDR schema requires ksiEvidence items to be objects with an
    # evidenceType from a fixed enum, not plain strings, so the SDR that
    # renders from these validates and is publishable. A collector observation
    # is Configuration/Audit Record evidence carried as evidenceText, with a
    # date. It is still telemetry: it does not assert the KSI is met.
    if is_tbd(record.get("evidence", [])):
        new_ev = []
        for check, fact in cfg:
            new_ev.append({
                "evidenceType": "Configuration",
                "evidenceDescription": (
                    f"AWS Config rule `{check['target']}` compliance, collected "
                    f"read-only by the SDR collector ({check['check_id']})."),
                "evidenceText": (
                    f"{check['target']} = {fact['compliance_type']} "
                    f"(region {fact.get('region')})"),
                "lastUpdated": (fact.get("collected_at") or "")[:10],
            })
        for pf in posture:
            # Log-style services (GuardDuty, CloudTrail) are Audit Record; the
            # configuration-posture services are Configuration evidence.
            etype = ("Audit Record"
                     if pf["service"] in ("guardduty", "cloudtrail", "security_hub")
                     else "Configuration")
            new_ev.append({
                "evidenceType": etype,
                "evidenceDescription": (
                    f"{pf['service']} {pf['check']} posture, collected read-only "
                    f"by the SDR collector in region {pf.get('region')}."),
                "evidenceText": f"{pf['service']}.{pf['check']} = {pf['status']}. "
                                f"{pf['detail']}",
                "lastUpdated": (pf.get("collected_at") or "")[:10],
            })
        if new_ev:
            record["evidence"] = new_ev
            changed = True
            notes.append(f"{kid}: filled {len(new_ev)} evidence object(s)")

    # extension.automation_verification: a single dated summary line, only if TBD.
    ext = record.get("extension", {})
    if isinstance(ext, dict) and is_tbd(ext.get("automation_verification", "")):
        n = len(cfg) + len(posture)
        ext["automation_verification"] = (
            f"Draft from collectors: {n} automated read-only check(s) observed "
            "for this indicator. Review each and confirm it demonstrates the "
            "measure before relying on it; a passing check is telemetry, not a "
            "compliance conclusion.")
        changed = True
        notes.append(f"{kid}: drafted automation_verification")

    return changed, notes


def main():
    ap = argparse.ArgumentParser(
        description="Deterministic fact-to-field pre-fill (reviewable diff).")
    ap.add_argument("--write", action="store_true",
                    help="write the proposed record store to the sidecar file")
    args = ap.parse_args()

    registry = load(REGISTRY)
    store = load(RECORD_STORE)
    if registry is None or store is None:
        print("Could not load the registry or the record store.")
        return 2

    config_by_rule, posture_by_service, latest_ts = load_all_facts()
    if not config_by_rule and not posture_by_service:
        print("No facts found in automation/facts/. Run the collector first:")
        print("    python automation/collectors/collect_facts.py --profile <ReadOnly>")
        return 1

    proposed = copy.deepcopy(store)
    ksi_records = proposed.get("ksi", {})
    all_notes = []
    filled = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        record = ksi_records.get(kid)
        if record is None:
            continue
        changed, notes = prefill_ksi(kid, record, ksi_entry,
                                     config_by_rule, posture_by_service)
        if changed:
            filled += 1
        all_notes.extend(notes)

    if filled == 0:
        print("No KSI fields were pre-filled. Either no backing facts matched, "
              "or the fields were already populated (pre-fill only touches "
              "TBD/empty template fields).")
        return 0

    before = json.dumps(store, indent=1, ensure_ascii=False).splitlines(keepends=True)
    after = json.dumps(proposed, indent=1, ensure_ascii=False).splitlines(keepends=True)
    diff = difflib.unified_diff(
        before, after,
        fromfile="records-store.json (current)",
        tofile="records-store.json (proposed pre-fill)")
    sys.stdout.writelines(diff)

    print(f"\nPre-fill summary (facts collected {latest_ts}):")
    for note in all_notes:
        print(f"  {note}")
    print(f"\n{filled} KSI(s) had at least one field pre-filled from facts.")
    print("This is a PROPOSAL. implementation_status and assessment were not "
          "touched. Review each line, then hand-edit the real record store; a "
          "passing check is telemetry, not a compliance conclusion.")

    if args.write:
        with open(SIDECAR, "w", encoding="utf-8", newline="\n") as f:
            json.dump(proposed, f, indent=1)
        print(f"\nWrote proposed record store to {os.path.relpath(SIDECAR, BASE)} "
              "(git-excluded). Diff it against the real store and apply what is "
              "correct by hand.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
