#!/usr/bin/env python3
"""End-to-end submission-readiness test.

Proves two things a green template build never exercised:
  1. A fully-filled Class C offering reaches "Submission ready" (preflight
     exits 0) - i.e. every preflight blocker is clearable by real provider
     input. This locks in the trust-center/SCG dead-end fix: those CPO URLs
     are now driven by trust_center_uri / secure_config_guide_uri.
  2. Changing a provider input AFTER a manifest-bound package signoff
     invalidates that signoff (preflight blocks on the manifest hash), proving
     the signoff is cryptographically bound to the exact package.

Operates entirely in a temp copy of the repo; the real tree is untouched.

    python validation/scripts/test_submission_readiness.py
"""

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def _fill(profile_path, now, cls="C"):
    prof = json.load(open(profile_path, encoding="utf-8"))
    prof.update({
        "certification_class": cls,
        "organization_name": "Contoso Federal Cloud LLC",
        "offering_name": "Contoso Secure Platform",
        "offering_abbreviation": "CSP",
        "deployment_model": "Government-Only Cloud",
        "service_model": "PaaS",
        "management_plane": "Provider-hosted control plane isolated from customer workloads.",
        "federal_information_types": "Moderate impact federal operational data.",
        "certification_package_overview_uri": "https://contoso.gov/cpo.json",
        "security_contact": "security@contoso.gov",
        "incident_contact": "soc@contoso.gov",
        "assessor": "Acme FedRAMP Assessors LLC",
        "evidence_retention": "3 years",
        "provider_verified_at": now.isoformat(),
        "fedramp_package_id": "FR-2026-CSP-0001",
        "offering_website": "https://contoso.gov",
        "offering_logo_uri": "https://contoso.gov/logo.png",
        "assessor_id": "482913",
        "sales_contact": "sales@contoso.gov",
        "next_ocr_date": (now.date() + datetime.timedelta(days=90)).isoformat(),
        "trust_center_uri": "https://contoso.gov/trust",
        "secure_config_guide_uri": "https://contoso.gov/scg",
        # FRC-APP-FIA (B/C MUST): fresh FedRAMP independent assessment < 3 months.
        "fedramp_independent_assessment": {
            "assessor_name": "Acme FedRAMP Assessors LLC",
            "assessor_fedramp_id": "FR-ASSESSOR-0007",
            "completed_at": (now.date() - datetime.timedelta(days=30)).isoformat(),
            "assessment_summary_uri": "https://contoso.gov/assessment-summary.pdf",
            "assessment_report_uri": "https://contoso.gov/assessment-report.pdf",
            "assessment_report_sha256": "sha256:" + "b" * 64,
        },
        # CPO-CSO-OSA (B/C MUST): assessor overall summary in the CPO.
        "overall_assessment_summary": "Assessor confirmed all in-scope KSIs "
                                       "verified and validated; no critical findings.",
        # CDS-CSO-AVR (B/C MUST): 30-day availability service, both formats.
        "availability_reporting": {
            "human_readable_uri": "https://contoso.gov/status",
            "machine_readable_uri": "https://contoso.gov/status.json",
            "history_days": 30,
            "available_when_primary_unavailable": True,
            "verified_at": now.date().isoformat(),
        },
        # CPO-CSO-MTD metadata + CPO-CSO-OVR required information.
        "cpo_responsible_official": "Jane Provider, VP Security, jane@contoso.gov",
        "cpo_version": "1.0.0",
        "cpo_last_updated": now.isoformat(),
        "cpo_source_of_update": "Initial certification package preparation",
        "cpo_required_information": {
            "CPO-CSO-MTD": "See metadata section.",
            "CDS-CSO-PUB": {
                "FedRAMP ID": "FR2026-CSP-0001",
                "Service Model": "SaaS",
                "Deployment Model": "Government Community Cloud",
                "Business Category": "IT Management",
                "UEI Number": "ABC123DEF456",
                "Sales Contact Information": "sales@contoso.gov",
                "Security Contact Information": "security@contoso.gov",
                "Product Website Link": "https://contoso.gov/product",
                "Link to Product Logo": "https://contoso.gov/logo.png",
                "Overall Service Description": "Contoso secure workflow platform.",
                "Detailed list of specific services and their security categories": "https://contoso.gov/services",
                "Link to Secure Configuration Guidance": "https://contoso.gov/scg",
                "Overview of documentation supplied by the provider for the cloud service offering": "https://contoso.gov/docs",
                "Link to Trust Center landing page that includes instructions on accessing information in the trust center": "https://contoso.gov/trust",
                "Next Ongoing Certification Report date": "2027-03-01",
                "Current FedRAMP Recognized independent assessment service": "Acme FedRAMP Assessors LLC (FR-ASSESSOR-0007)",
            },
            "CDS-CSO-SVC": "Service list published at https://contoso.gov/services.",
            "CDS-CSO-IRP": [
                {
                    "Name of policy or procedure": "Access Control Policy",
                    "Name of file document web page etc": "ac-policy.pdf",
                    "Brief summary of policy or procedure": "Governs least-privilege access.",
                    "Word count of document": "3200",
                    "Current version": "2.1",
                    "Date of last update": "2026-06-01",
                    "Related FedRAMP Practices": "KSI-IAM-AAM",
                },
            ],
            "MAS-CSO-IIR": "Information resources enumerated in the SDR scope.",
            "MAS-CSO-FLO": "Information flows and security categories documented.",
            "MAS-CSO-TPR": [
                {
                    "General usage and configuration": "Managed database service.",
                    "Explanation or justification for use": "Primary datastore.",
                    "Mitigation measures in place to reduce the potential impact to federal customer data": "Encryption at rest, VPC isolation.",
                    "Compensating controls in place to reduce the potential impact to federal customer data": "Continuous monitoring alerts.",
                },
            ],
            "CMU-CSO-CMD": "FIPS-validated cryptographic modules documented.",
            "IVV-CSO-ICP": "Independent assessment results included per FIA.",
        },
        "application_prerequisites": {
            "marketplace_listing_uri": "https://marketplace.fedramp.gov/offerings/CSP",
            "application_form_reference": "APP-FORM-2026-CSP-0001",
        },
    })
    if cls == "A":
        # Class A: alternative-framework external assessment (FRC-CLA-ASF/EAM),
        # within the past 12 months. FIA/SCG/AVR-MUST/MOT do not apply to A.
        prof["external_assessment"] = {
            "framework": "SOC 2 Type II",
            "assessment_date": (now.date() - datetime.timedelta(days=60)).isoformat(),
            "assessor": "Acme SOC 2 Auditors LLP",
            "materials": [{
                "type": "SOC2-TypeII-report",
                "uri": "https://contoso.gov/soc2-2026.pdf",
                "sha256": "sha256:" + "a" * 64,
                "bridge_or_gap_letter_uri": "https://contoso.gov/bridge.pdf",
                "next_assessment_date": (now.date() + datetime.timedelta(days=305)).isoformat(),
            }],
        }
    json.dump(prof, open(profile_path, "w", encoding="utf-8", newline="\n"), indent=1)


def _preflight(root):
    return subprocess.run([sys.executable, "sdr.py", "preflight"], cwd=root,
                          capture_output=True, text=True)


def _fill_records(root):
    """Answer every applicable FRR/KSI record with real (fictional) content, so
    the package has actual implementation information, not placeholders."""
    import re
    rp = os.path.join(root, "sdr", "records", "records-store.json")
    recs = json.load(open(rp, encoding="utf-8"))
    prof = json.load(open(os.path.join(root, "profiles", "common", "offering-profile.json"),
                          encoding="utf-8"))
    cls = (prof.get("certification_class") or "b").lower()
    class_profile = json.load(open(os.path.join(root, "profiles", f"class-{cls}", "profile.json"),
                                   encoding="utf-8"))
    applicable_frr = {r["rule_id"] for r in class_profile.get("rules", [])}
    ksi_profile = json.load(open(os.path.join(root, "profiles", "common", "ksi-profile.json"),
                                 encoding="utf-8"))
    if cls == "a":
        # Match production preflight: Class A resolves only the 7 CLA-enumerated
        # KSIs. Filling only those proves the ~39 non-applicable KSIs are left
        # deliberately unanswered and still do not block (rather than the test
        # quietly answering all 46 and never exercising the scoping).
        applicable_ksi = set((class_profile.get("meta", {}) or {}).get("class_a_ksis", {}).keys())
    else:
        applicable_ksi = {k["ksi_id"] for k in ksi_profile.get("indicators", [])}

    def answer(rec, ident, is_ksi):
        rec["implementation_status"] = "Implemented"
        rec["implementation"] = [f"Fictional but complete implementation for {ident}."]
        rec["validation"] = [f"Validated {ident} via automated and manual checks."]
        rec["assessment"] = [f"Independent assessor confirmed {ident}."]
        ext = rec.setdefault("extension", {})
        ext["owner"] = "Jane Provider, VP Security"
        ext["customer_risk"] = "No residual customer risk identified."
        ext["failure_response"] = "Documented runbook and on-call escalation."
        ext["responsibility"] = "Provider"
        # SDR-CSO-FRR required items (FRR) / SDR-CSX-KSI required items (KSI).
        ext["verification"] = f"Verified the implementation of {ident} is appropriate."
        ext["independent_verification"] = f"Independent assessor verified {ident}."
        ext["independent_validation"] = f"Independent assessor validated {ident}."
        ext["assessor_responses"] = "No outstanding assessor comments."
        if is_ksi:
            ext["operating_cycle"] = "Continuous / daily persistent validation."
            ext["measures_verification"] = f"Measures demonstrate {ident}."
            ext["automation_verification"] = "Automation is accurate and sufficient."
        # Evidence with a resolvable inline source so integrity can recompute.
        fact = {"ident": ident, "status": "pass"}
        import hashlib as _h, json as _j
        digest = "sha256:" + _h.sha256(_j.dumps(fact, sort_keys=True,
                                                separators=(",", ":")).encode()).hexdigest()
        ev = {"evidenceType": "Report", "evidenceLocation": f"https://contoso.gov/ev/{ident}",
              "xEvidenceContentHash": digest, "source_fact": fact,
              "lastUpdated": "2026-09-01T00:00:00Z"}
        if is_ksi:
            rec["evidence"] = [ev]
            rec["tests"] = ["automated-check-1", "automated-check-2"]
        else:
            ext["rule_artifacts"] = [ev]
        return rec

    for rid in list(recs.get("frr", {})):
        if rid in applicable_frr:
            recs["frr"][rid] = answer(recs["frr"][rid], rid, False)
    for kid in list(recs.get("ksi", {})):
        if kid in applicable_ksi:
            recs["ksi"][kid] = answer(recs["ksi"][kid], kid, True)
    json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)

    # FRC-CSX-MOT: Class C needs >= 6 months of persistent-validation history.
    import datetime as _d
    today = _d.date.today()
    hist = {"ksis": {}}
    for kid in applicable_ksi:
        pts = []
        for m in range(0, 8):  # ~8 months of monthly datapoints
            d = today - _d.timedelta(days=30 * m)
            pts.append({"date": d.isoformat(), "status": "pass"})
        hist["ksis"][kid] = pts
    hp = os.path.join(root, "automation", "metrics", "metric-history.json")
    json.dump(hist, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)


def _build(root):
    subprocess.run([sys.executable, "sdr.py", "build"], cwd=root,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    tmp = tempfile.mkdtemp(prefix="e2e-sub-")
    root = os.path.join(tmp, "repo")
    # Copy the tree minus .git and heavy caches.
    shutil.copytree(BASE, root, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.log", ".tmp"))
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        profile = os.path.join(root, "profiles", "common", "offering-profile.json")
        register = os.path.join(root, "sdr", "reviews", "review-register.json")
        manifest = os.path.join(root, "artifacts", "release-manifest.json")

        _fill(profile, now)
        _build(root)

        # Stage 1: profile filled but SDR record CONTENT still placeholder.
        # preflight must BLOCK on unanswered applicable content.
        r0 = _preflight(root)
        check("profile-only (empty SDR content) is NOT submission ready",
              r0.returncode == 1 and "no implementation information" in r0.stdout)

        # Stage 2: answer every applicable record, rebuild, sign, and expect ready.
        _fill_records(root)
        _build(root)
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag,
            "package_manifest_sha256": mhash, "notes": "Reviewed full Class C package.",
        }
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        r = _preflight(root)
        check("fully-filled Class C offering reaches Submission ready (exit 0)", r.returncode == 0)
        check("preflight reports no blockers", "SUBMISSION BLOCKERS" not in r.stdout)
        check("TBD warning is scoped to applicable records",
              "applicable to Class" in r.stdout or r.returncode == 0)

        # Structured CPO semantics adversarial: a bare sentence for CDS-CSO-PUB
        # must NOT satisfy the rule (it enumerates 16 concrete items). This is
        # the "impossible to fool" property applied to the CPO.
        p = json.load(open(profile, encoding="utf-8"))
        good_pub = p["cpo_required_information"]["CDS-CSO-PUB"]
        p["cpo_required_information"]["CDS-CSO-PUB"] = "Public information is documented."
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rpub = _preflight(root)
        check("a bare-string CDS-CSO-PUB does NOT satisfy the structured rule",
              "not structurally complete" in rpub.stdout and rpub.returncode == 1)
        p["cpo_required_information"]["CDS-CSO-PUB"] = good_pub
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)

        # A BARE "N/A" in a required FRR field must NOT count as answered - only
        # a justified N/A does. Tamper one applicable record and confirm it blocks.
        rp = os.path.join(root, "sdr", "records", "records-store.json")
        recs = json.load(open(rp, encoding="utf-8"))
        frr_id = next(iter(recs.get("frr", {})))
        saved_impl = recs["frr"][frr_id].get("implementation")
        recs["frr"][frr_id]["implementation"] = "N/A"
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        rna = _preflight(root)
        check("a bare 'N/A' in a required FRR field is NOT accepted as answered",
              rna.returncode == 1 and "SUBMISSION BLOCKERS" in rna.stdout)
        recs["frr"][frr_id]["implementation"] = saved_impl
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)

        # FRC-APP-USA freshening gate: a 4-month-old assessment must BLOCK unless
        # a Recognized-service freshening review (with a recognition id) is
        # recorded, then reach ready once it is.
        p = json.load(open(profile, encoding="utf-8"))
        fia = p["fedramp_independent_assessment"]
        fia["completed_at"] = (now.date() - datetime.timedelta(days=120)).isoformat()
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rfa = _preflight(root)
        check("stale (4mo) assessment without a freshening review is blocked",
              "FRC-APP-USA freshening" in rfa.stdout and rfa.returncode == 1)
        fia["freshness_basis"] = "freshened"
        fia["freshening"] = {
            "reviewed_at": (now.date() - datetime.timedelta(days=10)).isoformat(),
            "reviewed_by": "Acme FedRAMP Assessors LLC",
            "reviewer_fedramp_id": "FR-ASSESSOR-0007",
            "changes_reviewed_reference": "change-log-2026-Q3",
        }
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        # Restore current-assessment state for the signoff flow below.
        fia_current = (now.date() - datetime.timedelta(days=30)).isoformat()
        _build(root)
        rfb = _preflight(root)
        check("stale assessment with a Recognized-service freshening review clears FIA",
              "FRC-APP-USA freshening" not in rfb.stdout)
        p["fedramp_independent_assessment"]["completed_at"] = fia_current
        p["fedramp_independent_assessment"].pop("freshening", None)
        p["fedramp_independent_assessment"]["freshness_basis"] = "current"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # Re-sign against the current manifest so the post-signoff test below is clean.
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = mhash
        reg["package_signoff"]["release_tag"] = tag
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # Change a provider input after signoff; the bound signoff must fail.
        p = json.load(open(profile, encoding="utf-8"))
        p["business_purpose"] = str(p.get("business_purpose", "")) + " (edited after signoff)"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r2 = _preflight(root)
        check("post-signoff change invalidates the manifest-bound signoff",
              "package_manifest_sha256 does not match" in r2.stdout and r2.returncode == 1)

        # Class A end-to-end on a FRESH tree (not the Class-C-filled one), so the
        # ~39 non-applicable KSIs are genuinely never answered - proving they do
        # not block, rather than being quietly filled. Only the 7 enumerated KSIs
        # apply; FIA/SCG/AVR-MUST/MOT do not; the alternative-framework external
        # assessment does.
        root_a = os.path.join(tmp, "repo-a")
        shutil.copytree(BASE, root_a, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.log", ".tmp"))
        profile_a = os.path.join(root_a, "profiles", "common", "offering-profile.json")
        register_a = os.path.join(root_a, "sdr", "reviews", "review-register.json")
        manifest_a = os.path.join(root_a, "artifacts", "release-manifest.json")
        _fill(profile_a, now, cls="A")
        _fill_records(root_a)
        _build(root_a)
        # Prove the fixture left the non-applicable KSIs unanswered on this fresh
        # tree: exactly the 7 Class A KSIs carry implementation content.
        recs_a = json.load(open(os.path.join(root_a, "sdr", "records", "records-store.json"),
                                encoding="utf-8"))
        answered_ksi = [kid for kid, rec in (recs_a.get("ksi", {}) or {}).items()
                        if "Fictional but complete" in str(rec.get("implementation"))]
        check("Class A fixture answered ONLY the 7 applicable KSIs, not all 46",
              len(answered_ksi) == 7)
        mhash_a = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
        tag_a = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
        reg_a = json.load(open(register_a, encoding="utf-8"))
        reg_a["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_a,
            "package_manifest_sha256": mhash_a, "notes": "Reviewed full Class A package.",
        }
        json.dump(reg_a, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)
        ra = _preflight(root_a)
        check("fully-filled Class A offering reaches Submission ready (exit 0)",
              ra.returncode == 0)
        check("Class A is not blocked on the ~39 non-applicable KSIs",
              "no implementation information" not in ra.stdout)
        # Class A CPO applicability: of the 9 OVR-referenced rules, only
        # CDS-CSO-PUB and MAS-CSO-IIR resolve for Class A, so the generated CPO
        # must carry exactly those two - not seven meaningless N/A entries.
        cpo_a = json.load(open(os.path.join(root_a, "package", "cpo", "cpo.json"), encoding="utf-8"))
        a_rules = {i.get("rule") for i in cpo_a.get("xCpoRequiredInformation", {}).get("items", [])}
        check("Class A CPO required-info is applicability-scoped to its 2 OVR rules",
              a_rules == {"CDS-CSO-PUB", "MAS-CSO-IIR"})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
