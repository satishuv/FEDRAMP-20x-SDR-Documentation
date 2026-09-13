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
    })
    json.dump(prof, open(profile_path, "w", encoding="utf-8", newline="\n"), indent=1)


def _preflight(root):
    return subprocess.run([sys.executable, "sdr.py", "preflight"], cwd=root,
                          capture_output=True, text=True)


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
        check("filled Class C offering reaches Submission ready (exit 0)", r.returncode == 0)
        check("preflight reports no blockers", "SUBMISSION BLOCKERS" not in r.stdout)

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
