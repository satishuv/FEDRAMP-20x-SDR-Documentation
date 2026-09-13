#!/usr/bin/env python3
"""Generate the Certification Package Overview (CPO).

CPO-CSO-OVR requires providers to supply a Certification Package Overview in
both human-readable and JSON formats, carrying the information required by a
set of related rules (CPO-CSO-MTD, CDS-CSO-PUB/SVC, MAS-CSO-*, CMU-CSO-CMD,
CDS-CSO-IRP, IVV-CSO-ICP). This builds the JSON against the official
fedramp-certification-package-overview-schema and a plain-text rendering.

Every provider-specific value comes from profiles/common/offering-profile.json,
and anything unprovided is an honest TBD placeholder. Where the official CPO
schema requires an enum value the profile has not supplied (deployment model,
service type) or a date (next Ongoing Certification Report), the generator emits
a schema-valid assumption AND records it in the doc's _cpoAssumptions list, so
it is never silently presented as a real provider fact. sdr.py preflight blocks
submission while the underlying profile fields are TBD, so an assumed value can
never reach a "submission ready" package. A green schema validation means the
document is well-formed, never that its contents are true or that the provider
is certified.

    python validation/scripts/build_cpo.py

Pipeline position: after build_sdr.py. Outputs:
    package/cpo/cpo.json   schema-valid Certification Package Overview
    package/cpo/cpo.md     human-readable rendering
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_JSON = os.path.join(BASE, "package", "cpo", "cpo.json")
OUT_MD = os.path.join(BASE, "package", "cpo", "cpo.md")

TBD = "TBD: Information has not been provided."
TBD_URI = "https://example.provider.gov-placeholder/tbd"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def val(v):
    return v if v not in (None, "") else TBD


def _repository(desc, url=None):
    # Minimal valid `repository` object per the CPO schema. A provider-supplied
    # url overrides the TBD placeholder; a TBD/unset value keeps the placeholder
    # so preflight blocks on an unfilled trust center / SCG.
    if not url or str(url).strip().startswith("TBD"):
        url = TBD_URI
    return {
        "repositoryType": ["Website"],
        "url": url,
        "repositoryDescription": desc,
        "authenticationRequired": False,
    }


def build_cpo(profile):
    cls = (profile.get("certification_class") or "b").upper()
    # certificationType enum is '20x' or 'Rev5'. Map the offering profile's
    # human label to the schema token.
    ctype = "Rev5" if "rev5" in (profile.get("certification_type") or "").lower() else "20x"

    # Any value the generator has to assume (because the profile is unset or
    # TBD) is recorded here so it is visible, not silently presented as a real
    # provider fact. sdr.py preflight already blocks submission while the
    # underlying profile fields are TBD, so these assumptions can never reach a
    # "submission ready" package.
    assumptions = []

    def _unset(v):
        return v is None or str(v).strip() == "" or str(v).strip().startswith("TBD")

    # deploymentModel must be one of the schema's enum values.
    DEPLOY_ENUM = {"public cloud": "Public Cloud", "government-only cloud": "Government-Only Cloud",
                   "hybrid cloud": "Hybrid Cloud", "community cloud": "Community Cloud",
                   "government community cloud": "Government Community Cloud"}
    raw_deploy = profile.get("deployment_model")
    deploy = DEPLOY_ENUM.get((raw_deploy or "").lower())
    if deploy is None:
        deploy = "Public Cloud"
        assumptions.append("deploymentModel assumed 'Public Cloud' because the "
                           "offering profile deployment_model is unset/unknown")
    # serviceType enum is SaaS/PaaS/IaaS.
    raw_stype = profile.get("service_model")
    stype = {"SAAS": "SaaS", "PAAS": "PaaS", "IAAS": "IaaS"}.get((raw_stype or "").upper())
    if stype is None:
        stype = "PaaS"
        assumptions.append("serviceType assumed 'PaaS' because the offering "
                           "profile service_model is unset/unknown")
    # nextOngoingCertificationReportDate: OCRs are due every 3 months
    # (CCM-OCR-AVL). Rather than a hard-coded past date, derive a plausible
    # FUTURE placeholder from the pinned dataset date + 3 months, and mark it.
    next_ocr = profile.get("next_ocr_date")
    if _unset(next_ocr):
        import datetime as _dt
        base = "-".join((profile.get("dataset_version") or "2026-01-01").split(".")[:3])
        try:
            d = _dt.date.fromisoformat(base)
        except ValueError:
            d = _dt.date.today()
        # add ~3 months (90 days) as a placeholder cadence anchor
        next_ocr = (d + _dt.timedelta(days=90)).isoformat()
        assumptions.append(f"nextOngoingCertificationReportDate is a placeholder "
                           f"({next_ocr}) derived from the dataset date + 3 months "
                           f"(CCM-OCR-AVL cadence); the provider must set next_ocr_date")
    # assessorID must be exactly 6 digits; use a clearly-placeholder value.
    aid = profile.get("assessor_id")
    if not (isinstance(aid, str) and aid.isdigit() and len(aid) == 6):
        aid = "000000"
    doc = {
        "serviceIdentification": {
            "fedRampPackageId": profile.get("fedramp_package_id") or "TBD-PACKAGE-ID",
            "providerName": val(profile.get("organization_name")),
            "serviceName": val(profile.get("offering_name")),
            "serviceAcronym": val(profile.get("offering_abbreviation")),
            "serviceDescription": val(profile.get("business_purpose")),
            "certificationType": ctype,
            "website": profile.get("offering_website") or TBD_URI,
            # logo must end in an image extension per schema; placeholder .png.
            "logo": profile.get("offering_logo_uri")
            or "https://example.provider.gov-placeholder/logo.png",
        },
        "serviceProperties": {
            "serviceType": [stype],
            "deploymentModel": deploy,
            "trustCenter": _repository(
                "FedRAMP-compatible trust center for Certification Data (CDS-CSO-UTC).",
                profile.get("trust_center_uri")),
            "secureConfigurationGuidance": _repository(
                "Secure Configuration Guide (SCG-CSO-RSC).",
                profile.get("secure_config_guide_uri")),
            "nextOngoingCertificationReportDate": next_ocr,
        },
        # contactInformation must contain at least a Security and a Sales
        # contact (CDS-CSO-PUB). Ship both as honest placeholders.
        "contactInformation": [
            {"contactType": "Security", "contactName": val(profile.get("security_contact"))},
            {"contactType": "Sales", "contactName": val(profile.get("sales_contact"))},
        ],
        "assessor": {
            "name": val(profile.get("assessor")),
            "assessorID": aid,
        },
    }
    doc["_cpoNote"] = (
        f"Class {cls} Certification Package Overview scaffold. Required by "
        "CPO-CSO-OVR. Fill provider values in profiles/common/offering-profile.json; "
        "TBD markers show what a human still owes. Not a compliance claim.")
    # CPO-CSO-OSA: Class B/C MUST include the assessor's overall assessment
    # summary (from IVV-IAS-OSA) in the CPO, without inappropriate modification.
    # Carried as a provider extension since the official CPO schema has no slot.
    summary = profile.get("overall_assessment_summary")
    if summary:
        doc["xOverallAssessmentSummary"] = {
            "cr26_rule": "CPO-CSO-OSA",
            "source_rule": "IVV-IAS-OSA (assessor-supplied)",
            "summary": summary,
        }
    if assumptions:
        doc["_cpoAssumptions"] = assumptions
    return doc


def render_md(profile, doc):
    L = []
    a = L.append
    si = doc["serviceIdentification"]
    a("Certification Package Overview")
    a(f"{si['serviceName']} ({si['serviceAcronym']})")
    a("")
    a(f"Provider: {si['providerName']}")
    a(f"Certification type: {si['certificationType']}")
    a(f"Certification class: Class {(profile.get('certification_class') or 'b').upper()}")
    a(f"Service description: {si['serviceDescription']}")
    a(f"Website: {si['website']}")
    a("")
    a("Service properties")
    sp = doc["serviceProperties"]
    a(f"Service type: {', '.join(sp['serviceType'])}")
    a(f"Deployment model: {sp['deploymentModel']}")
    a(f"Next Ongoing Certification Report date: {sp['nextOngoingCertificationReportDate']}")
    a(f"Trust center: {sp['trustCenter']['url']}")
    a(f"Secure Configuration Guidance: {sp['secureConfigurationGuidance']['url']}")
    a("")
    a("Assessor")
    a(f"Name: {doc['assessor']['name']}")
    a("")
    a("This Certification Package Overview is a generated scaffold required by "
      "CPO-CSO-OVR. TBD markers indicate information a human must still supply. "
      "A schema-valid document is not a compliance determination.")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no CPO is generated.")
        return 1
    doc = build_cpo(profile)
    dump_json(doc, OUT_JSON)
    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_md(profile, doc))
    print(f"CPO written: {os.path.relpath(OUT_JSON, BASE)} and .md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
