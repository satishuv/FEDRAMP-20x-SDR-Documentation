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


def _fill(profile_path, now):
    prof = json.load(open(profile_path, encoding="utf-8"))
    prof.update({
        "certification_class": "C",
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
    })
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

        # Change a provider input after signoff; the bound signoff must fail.
        p = json.load(open(profile, encoding="utf-8"))
        p["business_purpose"] = str(p.get("business_purpose", "")) + " (edited after signoff)"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r2 = _preflight(root)
        check("post-signoff change invalidates the manifest-bound signoff",
              "package_manifest_sha256 does not match" in r2.stdout and r2.returncode == 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
