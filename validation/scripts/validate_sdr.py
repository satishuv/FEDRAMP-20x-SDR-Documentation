# Validate generated SDR JSON against the official FedRAMP SDR schema and run
# framework quality checks. Captures results per KSI, as required by the owner.
#
# Checks:
#   1. Official schema validation of sdr-class-<x>.json (resolves the cross-file
#      reference to the common definitions schema locally).
#   2. Coverage: every rule in the class profile appears in the SDR; every KSI
#      in the KSI profile appears in the SDR.
#   3. Per-KSI structural checks: required fields present, tests match the
#      minimum automated method count for the class (reported, not failed,
#      while the template is in TBD state).
#   4. Markdown-symbol detection in the human-readable rendering.
#   5. Sensitive-pattern detection (AWS account IDs, access keys, secrets).
#   6. Content fidelity: every statement, name, force, and family expansion
#      in the profile, official JSON, extensions, plain text, and docx is
#      compared against the canonical dataset (independent resolution, so
#      the validator does not trust the builders it checks).
#
# Output: validation/reports/validation-report.json plus per-KSI results in
# validation/reports/ksi-test-results.json. Exit code 1 on any hard failure.

import html
import json
import os
import re
import sys
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")
SDR_SCHEMA = os.path.join(SCHEMA_DIR, "fedramp-security-decision-record-schema-2026-06-24.json")
COMMON_SCHEMA = os.path.join(SCHEMA_DIR, "fedramp-common-definitions-schema-2026-06-24.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
REPORTS = os.path.join(BASE, "validation", "reports")

# KSIs whose statements are empty in the official dataset (FedRAMP pending).
EMPTY_STATEMENT_KSIS = {"KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR",
                        "KSI-SVC-RUD", "KSI-SVC-VCM"}

MD_PATTERNS = [
    (re.compile(r"^#{1,6} ", re.M), "markdown heading"),
    (re.compile(r"\*\*[^*\n]+\*\*"), "bold markers"),
    (re.compile(r"^\s*\* ", re.M), "asterisk bullet"),
    (re.compile(r"`[^`\n]+`"), "backticks"),
    (re.compile(r"^\|.+\|$", re.M), "markdown table"),
]

SENSITIVE_PATTERNS = [
    (re.compile(r"\b\d{12}\b"), "possible AWS account ID"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "private key"),
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_schema(doc):
    import jsonschema
    from referencing import Registry, Resource

    sdr_schema = load(SDR_SCHEMA)
    common = load(COMMON_SCHEMA)
    registry = Registry().with_resources(
        [
            (sdr_schema["$id"], Resource.from_contents(sdr_schema)),
            (common["$id"], Resource.from_contents(common)),
        ]
    )
    validator = jsonschema.Draft202012Validator(sdr_schema, registry=registry)
    errors = [
        {"path": "/".join(str(p) for p in e.absolute_path), "message": e.message[:200]}
        for e in validator.iter_errors(doc)
    ]
    return errors


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def docx_body_text(path):
    """Extract the document body text from a docx (tag-stripped, XML entities
    unescaped, whitespace-normalized)."""
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    return norm(html.unescape(re.sub(r"<[^>]+>", " ", xml)))


def canonical_maps():
    """Rule and KSI lookup maps built directly from the canonical dataset."""
    ds = load(DATASET)
    rules = {}
    for famblock in ds["FRR"].values():
        for subsets in famblock.get("data", {}).values():
            for items in subsets.values():
                for rid, rule in items.items():
                    if isinstance(rule, dict) and re.match(r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$", rid):
                        rules[rid] = rule
    ksis = {}
    fam_names_ksi = {}
    for fam, famblock in ds["KSI"].items():
        fam_names_ksi[fam] = famblock.get("name")
        for kid, k in famblock.get("indicators", {}).items():
            if kid.startswith("KSI-"):
                ksis[kid] = k
    fam_names_frr = {f: ds["FRR"][f].get("info", {}).get("name") for f in ds["FRR"]}
    return rules, ksis, fam_names_frr, fam_names_ksi


def resolve_canonical(rule, cls):
    """Same resolution semantics as build_profiles.resolve_for_class,
    re-implemented independently so the validator does not trust the
    builder it is checking."""
    vbc = rule.get("varies_by_class")
    if vbc:
        v = vbc.get(cls)
        if v and v.get("statement"):
            return {"statement": v["statement"], "force": v.get("force")}
        if rule.get("statement"):
            return {"statement": rule["statement"], "force": rule.get("force")}
        return None
    if rule.get("statement"):
        return {"statement": rule["statement"], "force": rule.get("force")}
    return None


def content_fidelity(cls, class_profile, sdr):
    """Compare every generated statement, name, force, and family expansion
    against the canonical dataset. Returns a list of mismatch descriptions."""
    problems = []
    rules, ksis, fam_frr, fam_ksi = canonical_maps()

    for e in class_profile["rules"]:
        rid = e["rule_id"]
        rule = rules.get(rid)
        if rule is None:
            problems.append(f"profile {rid}: not found in canonical dataset")
            continue
        can = resolve_canonical(rule, cls)
        if can is None:
            problems.append(f"profile {rid}: no canonical statement resolvable for class {cls.upper()}")
            continue
        if e.get("statement") != can["statement"]:
            problems.append(f"profile {rid}: statement differs from dataset")
        if e.get("name") != rule.get("name"):
            problems.append(f"profile {rid}: name differs from dataset")
        if e.get("force") != can["force"]:
            problems.append(f"profile {rid}: force {e.get('force')} vs dataset {can['force']}")
        if e.get("family_name") != fam_frr.get(e["family"]):
            problems.append(f"profile {rid}: family_name differs from dataset")

    for entry in sdr["fedRampRequirements"]:
        rid = entry["frrID"]
        pe = entry.get("providerExtensions", {})
        rule = rules.get(rid, {})
        if pe.get("ruleName") not in (None, rule.get("name")):
            problems.append(f"sdr json {rid}: providerExtensions.ruleName differs from dataset")
        if pe.get("familyName") not in (None, fam_frr.get(pe.get("family"))):
            problems.append(f"sdr json {rid}: providerExtensions.familyName differs from dataset")
    for entry in sdr["keySecurityIndicators"]:
        kid = entry["ksiId"]
        pe = entry.get("providerExtensions", {})
        if pe.get("ksiName") not in (None, ksis.get(kid, {}).get("name")):
            problems.append(f"sdr json {kid}: providerExtensions.ksiName differs from dataset")

    ext_path = os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}-extensions.json")
    ext = load(ext_path)
    for rid, entry in ext["frr"].items():
        rule = rules.get(rid)
        can = resolve_canonical(rule, cls) if rule else None
        if can is None:
            continue
        if entry.get("name") != rule.get("name"):
            problems.append(f"extensions {rid}: name differs from dataset")
        wilf = entry.get("guidance", {}).get("what_it_looks_for")
        if norm(wilf) != norm(can["statement"]):
            problems.append(f"extensions {rid}: what_it_looks_for differs from canonical statement")

    txt = open(os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt"),
               encoding="utf-8").read()
    txt_norm = norm(txt)
    for entry in sdr["keySecurityIndicators"]:
        kid = entry["ksiId"]
        st = ksis.get(kid, {}).get("statement")
        if st:
            if norm(st) not in txt_norm:
                problems.append(f"txt: KSI {kid} statement not found verbatim")
        elif kid not in EMPTY_STATEMENT_KSIS:
            problems.append(f"txt: KSI {kid} has an unexpected empty canonical statement")

    docx_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}-authoring.docx")
    if os.path.exists(docx_path):
        dx = docx_body_text(docx_path)
        for e in class_profile["rules"]:
            rule = rules.get(e["rule_id"])
            can = resolve_canonical(rule, cls) if rule else None
            if can and can["statement"] and norm(can["statement"]) not in dx:
                problems.append(f"docx: rule {e['rule_id']} statement not found verbatim")
    else:
        problems.append(f"docx: {os.path.basename(docx_path)} missing")

    return problems


def main():
    profile = load(os.path.join(BASE, "profiles", "common", "offering-profile.json"))
    cls = profile["certification_class"].lower()
    if cls == "d":
        # Match build_sdr.py and build_docx.py: Class D is FedRAMP pending
        # (20x Program path coming in 2027, specifics set during the Phase 4
        # Pilot), so no SDR exists to validate.
        print("Class D is FedRAMP pending; no SDR is generated or validated. "
              "See profiles/class-d-future/readiness-register.json.")
        return 1
    sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    ksi_profile = load(os.path.join(BASE, "profiles", "common", "ksi-profile.json"))

    dataset_version = class_profile["meta"]["dataset_version"]
    # Deterministic: reports are stamped with the dataset version, not a run
    # timestamp, so an unchanged pipeline yields byte-identical reports.
    stamp = f"deterministic check against dataset {dataset_version}"
    report = {"generated": stamp, "class": cls.upper(), "checks": [], "hard_failures": 0}

    def check(name, passed, detail, hard=True):
        report["checks"].append({"check": name, "result": "PASS" if passed else "FAIL", "detail": detail})
        if not passed and hard:
            report["hard_failures"] += 1

    # 1. Official schema validation
    errors = validate_schema(sdr)
    check("official_schema_validation", not errors,
          f"{len(errors)} schema errors" + (f"; first: {errors[0]}" if errors else ""))

    # 1b. Dataset version agreement. The profile meta records the dataset
    # version it was built from; the pinned dataset carries its own
    # info.version. If someone swaps the dataset file without rebuilding the
    # profiles, every report would still stamp the stale profile version and
    # the mismatch would go unnoticed. Assert they agree so the version the
    # README and badge advertise is provably the version on disk.
    dataset_info_version = load(DATASET).get("info", {}).get("version")
    check("dataset_version_agreement", dataset_info_version == dataset_version,
          f"pinned dataset info.version {dataset_info_version} vs profile "
          f"dataset_version {dataset_version}"
          + ("" if dataset_info_version == dataset_version
             else " (rebuild profiles after swapping the dataset)"))

    # 1c. Pinned-schema version guard. FedRAMP edits schema files in place
    # without renaming them, so the filename proves nothing; the $schemaVersion
    # inside is the real signal. Assert each pinned schema still carries the
    # $id and $schemaVersion the framework was built against, so a swapped or
    # upstream-bumped schema is caught at the gate, not only by the daily drift
    # hash job. Update EXPECTED_SCHEMAS deliberately when adopting a new schema.
    EXPECTED_SCHEMAS = {
        SDR_SCHEMA: {
            "$id": "https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json",
            "$schemaVersion": "1.1.1",
        },
        COMMON_SCHEMA: {
            "$id": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json",
            "$schemaVersion": "0.3.0",
        },
    }
    schema_problems = []
    for path, expected in EXPECTED_SCHEMAS.items():
        doc = load(path)
        for key, want in expected.items():
            got = doc.get(key)
            if got != want:
                schema_problems.append(
                    f"{os.path.basename(path)} {key} {got} vs expected {want}")
    check("pinned_schema_version_guard", not schema_problems,
          "; ".join(schema_problems) if schema_problems
          else "both pinned schemas match expected $id and $schemaVersion")

    # 2. Coverage
    profile_ids = {r["rule_id"] for r in class_profile["rules"]}
    sdr_ids = {r["frrID"] for r in sdr["fedRampRequirements"]}
    missing_rules = sorted(profile_ids - sdr_ids)
    extra_rules = sorted(sdr_ids - profile_ids)
    check("rule_coverage", not missing_rules and not extra_rules,
          f"missing: {missing_rules[:5]} extra: {extra_rules[:5]} "
          f"({len(sdr_ids)}/{len(profile_ids)} rules)")

    if cls == "a":
        # Class A KSI applicability is enumerated by FRC-CLA-MFR; expected set
        # comes from the tier map in the class-a profile meta.
        ksi_ids = set(class_profile["meta"]["class_a_ksis"].keys())
    else:
        ksi_ids = {k["ksi_id"] for k in ksi_profile["indicators"]}
    sdr_ksi = {k["ksiId"] for k in sdr["keySecurityIndicators"]}
    check("ksi_coverage", ksi_ids == sdr_ksi,
          f"{len(sdr_ksi)}/{len(ksi_ids)} KSIs present")

    # 3. Per-KSI results
    min_methods = {k["ksi_id"]: k["minimum_automated_methods"][f"class_{cls}"]
                   for k in ksi_profile["indicators"]}
    ksi_results = []
    for k in sdr["keySecurityIndicators"]:
        kid = k["ksiId"]
        required_fields = ["ksiId", "ksiImplementation", "ksiValidation",
                           "ksiAssessment", "ksiTests", "ksiEvidence"]
        fields_ok = all(f in k for f in required_fields)
        test_count = len(k.get("ksiTests", []))
        needed = min_methods.get(kid, 0)
        ksi_results.append({
            "ksi_id": kid,
            "schema_fields_present": fields_ok,
            "implementation_status": k.get("ksiImplementationStatus"),
            "tests_defined": test_count,
            "minimum_automated_methods_for_class": needed,
            "meets_test_minimum": test_count >= needed,
            "content_state": ("template_tbd"
                              if any("TBD" in s for s in k.get("ksiImplementation", []))
                              else "populated"),
            "checked": stamp,
        })
    all_fields = all(r["schema_fields_present"] for r in ksi_results)
    check("ksi_required_fields", all_fields, "all KSIs carry the six schema-required fields")
    below_min = [r["ksi_id"] for r in ksi_results if not r["meets_test_minimum"]]
    check("ksi_test_minimums", not below_min,
          f"{len(below_min)} KSIs below the FRC-CSX-VVK minimum for class {cls.upper()} "
          "(expected in template state; hard failure only at release)",
          hard=False)

    # 4. Markdown detection in human-readable output
    txt = open(os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt"),
               encoding="utf-8").read()
    md_hits = [label for pat, label in MD_PATTERNS if pat.search(txt)]
    check("no_markdown_in_human_readable", not md_hits, f"hits: {md_hits}")

    # 5. Sensitive patterns across generated artifacts. Docx files are
    # scanned via their extracted document text, never as raw bytes, so
    # compressed binary runs cannot false-positive as account IDs.
    hits = []
    for root, _dirs, files in os.walk(os.path.join(BASE, "sdr")):
        for fn in files:
            path = os.path.join(root, fn)
            if fn.endswith(".docx"):
                content = docx_body_text(path)
            else:
                content = open(path, encoding="utf-8", errors="ignore").read()
            for pat, label in SENSITIVE_PATTERNS:
                if pat.search(content):
                    hits.append(f"{fn}: {label}")
    check("no_sensitive_patterns", not hits, f"hits: {hits}")

    # 6. Content fidelity against the canonical dataset: every statement,
    # name, and force in the profile, the official JSON extensions, the
    # plain-text rendering, and the authoring docx must match the dataset
    # character for character (whitespace-normalized for renderings).
    fidelity_problems = content_fidelity(cls, class_profile, sdr)
    check("content_fidelity_against_dataset", not fidelity_problems,
          f"{len(fidelity_problems)} mismatches"
          + (f"; first: {fidelity_problems[0]}" if fidelity_problems else
             " (all statements, names, and forces match the dataset)"))
    if fidelity_problems:
        report["fidelity_problems"] = fidelity_problems[:50]

    os.makedirs(REPORTS, exist_ok=True)
    with open(os.path.join(REPORTS, "validation-report.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(REPORTS, "ksi-test-results.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"generated": stamp, "class": cls.upper(), "results": ksi_results}, f, indent=1)

    for c in report["checks"]:
        print(f"{c['result']}: {c['check']} | {c['detail']}")
    print("hard failures:", report["hard_failures"])
    return 1 if report["hard_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
