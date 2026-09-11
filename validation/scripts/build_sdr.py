# Generate the Security Decision Record for the class selected in the offering
# profile, in both official-schema JSON and human-readable plain text.
#
# Pipeline position: build_catalogs.py -> build_profiles.py -> build_sdr.py -> validate_sdr.py
#
# Inputs:
#   profiles/common/offering-profile.json   central customization profile (selects class)
#   profiles/class-<x>/profile.json         resolved provider rules for the class
#   profiles/common/ksi-profile.json        all KSI indicators with per-class minimums
#   sdr/records/records-store.json          statement content per rule and KSI
#                                           (scaffolded with honest TBD markers on first run)
#
# Outputs:
#   sdr/json/sdr-class-<x>.json             official FedRAMP SDR schema document
#   sdr/json/sdr-class-<x>-extensions.json  provider operational metadata companion
#   sdr/human-readable/sdr-class-<x>.txt    plain-text rendering, no markdown symbols
#
# The official JSON contains only schema-defined properties so it stays portable.
# Everything richer lives in the extensions companion, keyed by frrID and ksiId.

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")

TBD = "TBD: Information has not been provided."


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def scaffold_records(rules, ksis):
    """Create the record store with honest placeholders. Existing content is
    never overwritten; this only runs when the store does not exist."""
    store = {
        "store_note": (
            "Statement content for every rule and KSI. Generic template text and "
            "TBD markers only in the public template. Reference-architecture "
            "examples are labeled as assumptions, never as confirmed implementations."
        ),
        "frr": {},
        "ksi": {},
    }
    for r in rules:
        store["frr"][r["rule_id"]] = {
            "implementation_status": "Not Implemented",
            "implementation": [TBD],
            "validation": [TBD],
            "assessment": [
                "TBD: Independent assessment has not been performed."
            ],
            # SDR-CSO-FRR requires seven information items per rule, but the
            # official schema carries only frrImplementation, frrValidation and
            # frrAssessment. Items 4 to 7 (independent verification, independent
            # validation, responses to assessor comments, rule-specific
            # artifacts) have no official field, so they live here.
            "extension": {
                "owner": TBD,
                "verification": TBD,
                "validation_frequency": TBD,
                "failure_condition": TBD,
                "failure_response": TBD,
                "evidence_freshness": TBD,
                "exception_reference": "None recorded",
                "independent_verification": TBD,
                "independent_validation": TBD,
                "assessor_responses": "None recorded",
                "rule_artifacts": [],
                "senior_official_acceptance": "Not required: rule is followed",
                "customer_risk": TBD,
                "responsibility": {
                    "aws": TBD,
                    "provider": TBD,
                    "customer": TBD,
                },
            },
        }
    for k in ksis:
        pending = k["content_status"].startswith("FedRAMP pending")
        store["ksi"][k["ksi_id"]] = {
            "implementation_status": "Not Implemented",
            "implementation": [
                "FedRAMP pending: this indicator has no statement in the official dataset yet."
                if pending
                else TBD
            ],
            "validation": [TBD],
            "assessment": ["TBD: Independent assessment has not been performed."],
            "tests": [],
            "evidence": [],
            # SDR-CSX-KMT. Class A MAY include historical metrics; Class B and
            # Class C MUST. Daily data is Class C only. The collector should
            # write these rather than a human.
            "historical_metrics": {
                "last_30_days": TBD,
                "up_to_one_year": TBD,
                "daily_data_reference": TBD,
            },
            "extension": {
                "owner": TBD,
                "measures": TBD,
                "operating_cycle": TBD,
                "metric_source": TBD,
                "pass_condition": TBD,
                "failure_condition": TBD,
                "failure_response": TBD,
                "known_limitation": TBD,
                # SDR-CSX-KSI items 3 and 4: verification that the measures
                # demonstrate the indicator, and that the automation behind
                # them is accurate and sufficient (or that automation is not
                # necessary). Neither has an official schema field.
                "measures_verification": TBD,
                "automation_verification": TBD,
                "assessor_responses": "None recorded",
                "customer_responsibility": TBD,
                "aws_responsibility": TBD,
                "provider_responsibility": TBD,
                "exception_reference": "None recorded",
            },
        }
    return store


def build_official(profile, rules, ksis, records):
    # metadata block is official as of schema 1.1.1 (2026-07-14 in-place
    # update to the 2026-06-24 schema file), per SDR-CSO-MTD.
    # Each entry also carries a providerExtensions object with the rule name
    # and the family short form spelled out. The official schema does not set
    # additionalProperties, so extra properties are permitted; keeping them in
    # one clearly isolated object preserves portability of the official fields.
    fam_names = load_family_names()
    # Deterministic: lastUpdated comes from the offering profile (bump
    # sdr_last_updated when record content changes), falling back to the
    # dataset version date, never a run timestamp.
    dataset_date = "-".join(profile["dataset_version"].split(".")[:3])
    last_updated = profile.get("sdr_last_updated") or f"{dataset_date}T00:00:00+00:00"
    doc = {
        "certificationPackageOverviewUri": profile["certification_package_overview_uri"],
        "metadata": {
            "version": profile["sdr_version"],
            "lastUpdated": last_updated,
            "updateSource": "build_sdr.py generator",
        },
        "fedRampRequirements": [],
        "keySecurityIndicators": [],
    }
    for r in rules:
        rec = records["frr"].get(r["rule_id"], {})
        fam = r["family"]
        doc["fedRampRequirements"].append(
            {
                "frrID": r["rule_id"],
                "frrImplementationStatus": rec.get("implementation_status", "Not Implemented"),
                "frrImplementation": rec.get("implementation", [TBD]),
                "frrValidation": rec.get("validation", [TBD]),
                "frrAssessment": rec.get("assessment", [TBD]),
                "providerExtensions": {
                    "ruleName": r["name"],
                    "family": fam,
                    "familyName": fam_names["frr"].get(fam, fam),
                    # SDR-CSO-FRR requires seven information items per applicable
                    # rule, but the official schema carries only frrImplementation,
                    # frrValidation and frrAssessment. The remaining required
                    # items (implementation/nonimplementation risk, independent
                    # verification, independent validation, responses to
                    # independent-review comments, and rule-specific artifacts)
                    # have no dedicated official field. The official schema does
                    # not set additionalProperties, so extra fields are permitted;
                    # they are carried here, inside the submitted document, so the
                    # required information travels WITH the SDR rather than in a
                    # separate sidecar a consumer might miss.
                    "xFedRampSemantic": frr_semantic(rec),
                },
            }
        )
    for k in ksis:
        rec = records["ksi"].get(k["ksi_id"], {})
        doc["keySecurityIndicators"].append(
            {
                "ksiId": k["ksi_id"],
                "ksiImplementationStatus": rec.get("implementation_status", "Not Implemented"),
                "ksiImplementation": rec.get("implementation", [TBD]),
                "ksiValidation": rec.get("validation", [TBD]),
                "ksiAssessment": rec.get("assessment", [TBD]),
                "ksiTests": rec.get("tests", []),
                "ksiEvidence": rec.get("evidence", []),
                "providerExtensions": {
                    "ksiName": k["name"],
                    "family": k["family"],
                    "familyName": k["family_name"],
                    # SDR-CSX-KSI requires five information items per KSI
                    # (measures/objectives, their cycle, verification of the
                    # measures, verification of the supporting automation, and
                    # validation) and SDR-CSX-KMT requires historical metrics by
                    # class. Only ksiValidation/ksiAssessment map to official
                    # fields, so the rest is carried here inside the submitted
                    # document.
                    "xFedRampSemantic": ksi_semantic(rec),
                },
            }
        )
    return doc


def _val(v):
    """Normalize a record value for emission: None becomes the TBD marker so a
    required field is never silently absent from the submitted document."""
    return v if v not in (None, "") else TBD


def frr_semantic(rec):
    """Assemble the SDR-CSO-FRR semantic block from a record-store entry so
    every required information item reaches the submitted SDR. Missing values
    surface as the honest TBD marker rather than disappearing."""
    ext = rec.get("extension", {})
    return {
        "implementationRisk": _val(ext.get("customer_risk")),
        "verification": _val(ext.get("verification")),
        "validationFrequency": _val(ext.get("validation_frequency")),
        "independentVerification": _val(ext.get("independent_verification")),
        "independentValidation": _val(ext.get("independent_validation")),
        "assessorResponses": ext.get("assessor_responses", "None recorded"),
        "ruleArtifacts": ext.get("rule_artifacts", []),
        "seniorOfficialAcceptance": ext.get(
            "senior_official_acceptance", "Not required: rule is followed"),
        "owner": _val(ext.get("owner")),
    }


def ksi_semantic(rec):
    """Assemble the SDR-CSX-KSI and SDR-CSX-KMT semantic block from a
    record-store entry. Historical metrics (Class B/C MUST) are emitted here
    instead of being dropped from the generated document."""
    ext = rec.get("extension", {})
    hm = rec.get("historical_metrics", {})
    return {
        "measures": _val(ext.get("measures")),
        "operatingCycle": _val(ext.get("operating_cycle")),
        "measuresVerification": _val(ext.get("measures_verification")),
        "automationVerification": _val(ext.get("automation_verification")),
        "assessorResponses": ext.get("assessor_responses", "None recorded"),
        "owner": _val(ext.get("owner")),
        "historicalMetrics": {
            "last30Days": _val(hm.get("last_30_days")),
            "upToOneYear": _val(hm.get("up_to_one_year")),
            "dailyDataReference": _val(hm.get("daily_data_reference")),
        },
    }


def load_notes():
    rule_notes = {}
    ksi_notes = {}
    rn_path = os.path.join(BASE, "traceability", "rule-notes.json")
    kn_path = os.path.join(BASE, "traceability", "ksi-notes.json")
    if os.path.exists(rn_path):
        rule_notes = load(rn_path)["rules"]
    if os.path.exists(kn_path):
        ksi_notes = load(kn_path)["indicators"]
    return rule_notes, ksi_notes


def load_family_names():
    path = os.path.join(BASE, "traceability", "family-names.json")
    if os.path.exists(path):
        return load(path)
    return {"frr": {}, "ksi": {}}


def expand_family(code, names):
    full = names.get(code)
    return f"{code} ({full})" if full and full != code else code


def build_extensions(profile, rules, ksis, records, cls):
    rule_notes, ksi_notes = load_notes()
    fam_names = load_family_names()
    ext = {
        "extension_note": (
            "Provider operational metadata companion to the official SDR JSON. "
            "Nonstandard fields live here so the official document remains "
            "schema-portable. Keyed by frrID and ksiId."
        ),
        "metadata": {
            "offering": profile["offering_name"],
            "certification_class": cls.upper(),
            "certification_path": profile["certification_path"],
            "aws_partition": profile["aws_partition"],
            "regions": [profile["primary_region"], profile["dr_region"]],
            "sdr_version": profile["sdr_version"],
            "schema_version": profile["schema_version"],
            "dataset_version": profile["dataset_version"],
            "generated": f"deterministic build from dataset {profile['dataset_version']}",
            "source_of_update": "build_sdr.py generator",
        },
        "frr": {},
        "ksi": {},
    }
    for r in rules:
        rec = records["frr"].get(r["rule_id"], {})
        note = rule_notes.get(r["rule_id"], {})
        entry = {
            "name": r["name"],
            "force": r["force"],
            "family": r["family"],
            "family_name": fam_names["frr"].get(r["family"], r["family"]),
            "guidance": {
                "what_it_looks_for": r["statement"],
                "official_notes": note.get("official_notes", []),
                "how_to_comply": note.get("how_to_comply_guidance", ""),
                "evidence_required": note.get("evidence_required", []),
                "evidence_source": note.get("evidence_source", ""),
                "note": ("How to comply is SAS advisory guidance, not FedRAMP "
                         "text. Fill the TBD fields below with the provider's "
                         "real implementation, validation, and owner."),
            },
            **rec.get("extension", {}),
        }
        if r.get("class_a_obligation"):
            entry["class_a_obligation"] = r["class_a_obligation"]
        ext["frr"][r["rule_id"]] = entry
    for k in ksis:
        rec = records["ksi"].get(k["ksi_id"], {})
        note = ksi_notes.get(k["ksi_id"], {})
        ext["ksi"][k["ksi_id"]] = {
            "name": k["name"],
            "family": k["family"],
            "family_name": k["family_name"],
            "content_status": k["content_status"],
            "minimum_automated_methods": k["minimum_automated_methods"][f"class_{cls}"],
            "historical_metrics_required": k["historical_metrics"][f"class_{cls}"],
            "guidance": {
                "what_it_looks_for": note.get("what_it_looks_for", ""),
                "how_to_comply": note.get("how_to_comply_guidance", ""),
                "evidence_required": note.get("evidence_required", []),
                "nist_controls": note.get("nist_controls", []),
                "note": ("How to comply is SAS advisory guidance, not FedRAMP "
                         "text. Fill the TBD fields below with the provider's "
                         "real implementation, validation, tests, and owner."),
            },
            **rec.get("extension", {}),
        }
    return ext


def render_human(profile, rules, ksis, records, cls):
    fam_names = load_family_names()
    L = []
    a = L.append
    a("SECURITY DECISION RECORD")
    a(f"{profile['offering_name']} ({profile['offering_abbreviation']})")
    a("")
    a(f"Certification type: {profile['certification_type']}")
    a(f"Certification class: Class {cls.upper()}")
    a(f"Certification path: {profile['certification_path']} Certification")
    a(f"AWS partition: {profile['aws_partition']}")
    a(f"Primary region: {profile['primary_region']}")
    a(f"Disaster recovery region: {profile['dr_region']}")
    a(f"SDR version: {profile['sdr_version']}")
    a(f"Generated from dataset version: {profile['dataset_version']}")
    a("Source of update: build_sdr.py generator")
    a("")
    a("This is a generic template record. Statements marked TBD require real")
    a("implementation facts before this record can support an assessment.")
    a("Reference architecture content is an assumption, not a confirmed system.")
    a("")
    a("1. FedRAMP Requirements")
    a("")
    for i, r in enumerate(rules, 1):
        rec = records["frr"].get(r["rule_id"], {})
        a(f"1.{i} {r['rule_id']} {r['name'] or ''}")
        a(f"FedRAMP rule: {r['rule_id']}")
        a(f"Rule family: {expand_family(r['family'], fam_names['frr'])}")
        a(f"Force: {r['force'] or 'stated in rule text'}")
        if r.get("class_a_obligation"):
            a(f"Class A obligation: {r['class_a_obligation']} (per FRC-CLA-MFR, RFR, or OFR)")
        a(f"Status: {rec.get('implementation_status', 'Not Implemented')}")
        for s in rec.get("implementation", []):
            a(f"Implementation: {s}")
        for s in rec.get("validation", []):
            a(f"Validation: {s}")
        for s in rec.get("assessment", []):
            a(f"Independent assessment: {s}")
        ext = rec.get("extension", {})
        a(f"Implementation or nonimplementation risk: {_val(ext.get('customer_risk'))}")
        a(f"Verification: {_val(ext.get('verification'))}")
        a(f"Independent verification: {_val(ext.get('independent_verification'))}")
        a(f"Independent validation: {_val(ext.get('independent_validation'))}")
        a(f"Responses to independent review comments: {ext.get('assessor_responses', 'None recorded')}")
        arts = ext.get("rule_artifacts", [])
        a(f"Rule-specific artifacts: {'; '.join(str(x) for x in arts) if arts else 'None recorded'}")
        a(f"Owner: {ext.get('owner', TBD)}")
        a("")
    a("2. Key Security Indicators")
    a("")
    for i, k in enumerate(ksis, 1):
        rec = records["ksi"].get(k["ksi_id"], {})
        ext = rec.get("extension", {})
        hm = rec.get("historical_metrics", {})
        a(f"2.{i} {k['ksi_id']} {k['name'] or ''}")
        a(f"KSI: {k['ksi_id']}")
        a(f"Family: {k['family']} ({k['family_name']})")
        if k["statement"]:
            a(f"Security outcome: {k['statement']}")
        else:
            a("Security outcome: FedRAMP pending, no statement in the official dataset yet.")
        a(f"Status: {rec.get('implementation_status', 'Not Implemented')}")
        for s in rec.get("implementation", []):
            a(f"Implementation: {s}")
        for s in rec.get("validation", []):
            a(f"Validation: {s}")
        for s in rec.get("assessment", []):
            a(f"Independent assessment: {s}")
        a(f"Measures and objectives: {_val(ext.get('measures'))}")
        a(f"Measurement cycle: {_val(ext.get('operating_cycle'))}")
        a(f"Verification of measures: {_val(ext.get('measures_verification'))}")
        a(f"Verification of supporting automation: {_val(ext.get('automation_verification'))}")
        a(f"Minimum automated methods for this class: {k['minimum_automated_methods'][f'class_{cls}']}")
        a(f"Historical metrics required for this class: {k['historical_metrics'][f'class_{cls}']}")
        a(f"Historical metrics, 30-day summary: {_val(hm.get('last_30_days'))}")
        a(f"Historical metrics, up to one year: {_val(hm.get('up_to_one_year'))}")
        a(f"Historical metrics, daily data reference (Class C): {_val(hm.get('daily_data_reference'))}")
        tests = rec.get("tests", [])
        a(f"Tests: {'; '.join(tests) if tests else 'None defined yet'}")
        a(f"Owner: {ext.get('owner', TBD)}")
        a("")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = profile["certification_class"].lower()
    if cls not in ("a", "b", "c"):
        print(f"Class {cls.upper()} SDR generation is not supported: "
              "Class D is FedRAMP pending (Phase 4 pilot).")
        return 1
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    rules = class_profile["rules"]
    ksis = load(KSI_PROFILE)["indicators"]
    if cls == "a":
        # Class A KSI applicability is enumerated by FRC-CLA-MFR; only the
        # listed KSIs go into the Class A SDR. The tier map is written into
        # the class-a profile meta by build_profiles.py.
        ksi_tier = class_profile["meta"]["class_a_ksis"]
        ksis = [k for k in ksis if k["ksi_id"] in ksi_tier]

    if os.path.exists(RECORDS):
        records = load(RECORDS)
        # merge-scaffold any rules or KSIs not yet in the store (for example
        # the FRC CLA rules that only appear in the Class A profile), without
        # touching existing content
        fresh = scaffold_records(rules, ksis)
        added = 0
        for rid, entry in fresh["frr"].items():
            if rid not in records["frr"]:
                records["frr"][rid] = entry
                added += 1
        for kid, entry in fresh["ksi"].items():
            if kid not in records["ksi"]:
                records["ksi"][kid] = entry
                added += 1
        if added:
            print(f"record store: {added} new entries scaffolded")
        # Backfill extension sub-keys added to the scaffold since the store was
        # written. Existing values are never touched, so authored content
        # survives; only absent keys are created, with their TBD placeholder.
        # Without this, a new SDR-CSO-FRR information item would only ever
        # appear on rules added after the change.
        added_keys = 0
        for kind in ("frr", "ksi"):
            for rid, entry in records[kind].items():
                template = fresh[kind].get(rid, {})
                for key, value in template.items():
                    if key == "extension":
                        ext = entry.setdefault("extension", {})
                        for ek, ev in value.items():
                            if ek not in ext:
                                ext[ek] = ev
                                added_keys += 1
                    elif key not in entry:
                        entry[key] = value
                        added_keys += 1
        if added_keys:
            print(f"record store: {added_keys} new extension fields backfilled")
    else:
        records = scaffold_records(rules, ksis)
        print("record store scaffolded:", RECORDS)

    # Backfill guidance into the record store so the file the provider edits
    # carries the instructions next to the fields being filled. Guidance is
    # regenerated every run (never author into it); authored content in the
    # other fields is never touched.
    rule_notes, ksi_notes = load_notes()
    fam_names = load_family_names()
    ksi_fam_by_id = {k["ksi_id"]: (k["family"], k["family_name"]) for k in ksis}
    for rid, entry in records["frr"].items():
        note = rule_notes.get(rid, {})
        rule = next((r for r in rules if r["rule_id"] == rid), None)
        fam = rule["family"] if rule else rid.split("-")[0]
        entry["fill_guidance"] = {
            "read_me": ("Fill implementation, validation, and the extension "
                        "fields below with the provider's real facts, then run "
                        "build_sdr.py to regenerate all outputs. Do not edit "
                        "the generated files in sdr/json or sdr/human-readable."),
            "rule_family": expand_family(fam, fam_names["frr"]),
            "what_it_looks_for": (rule["statement"] if rule else "See rule catalog."),
            "how_to_comply": note.get("how_to_comply_guidance", ""),
            "evidence_required": note.get("evidence_required", []),
        }
    for kid, entry in records["ksi"].items():
        note = ksi_notes.get(kid, {})
        fam_code, fam_name = ksi_fam_by_id.get(
            kid, (kid.split("-")[1], fam_names["ksi"].get(kid.split("-")[1], "")))
        entry["fill_guidance"] = {
            "read_me": ("Fill implementation, validation, tests, and the "
                        "extension fields below with the provider's real facts, "
                        "then run build_sdr.py to regenerate all outputs."),
            "ksi_family": f"{fam_code} ({fam_name})" if fam_name else fam_code,
            "what_it_looks_for": note.get("what_it_looks_for", ""),
            "how_to_comply": note.get("how_to_comply_guidance", ""),
            "evidence_required": note.get("evidence_required", []),
        }
    dump(records, RECORDS)

    official = build_official(profile, rules, ksis, records)
    ext = build_extensions(profile, rules, ksis, records, cls)
    text = render_human(profile, rules, ksis, records, cls)

    dump(official, os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))
    dump(ext, os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}-extensions.json"))
    txt_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt")
    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

    print(f"class: {cls.upper()}")
    print("rules in SDR:", len(official["fedRampRequirements"]))
    print("ksis in SDR:", len(official["keySecurityIndicators"]))
    print("outputs written to sdr/json and sdr/human-readable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
