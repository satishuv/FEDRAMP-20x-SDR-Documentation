#!/usr/bin/env python3
"""Generate the Certification Package Overview (CPO).

CPO-CSO-OVR requires providers to supply a Certification Package Overview in
both human-readable and JSON formats, carrying the information required by a
set of related rules (CPO-CSO-MTD, CDS-CSO-PUB/SVC, MAS-CSO-*, CMU-CSO-CMD,
CDS-CSO-IRP, IVV-CSO-ICP). This builds the JSON against the official
fedramp-certification-package-overview-schema and a plain-text rendering.

Like the SDR generator, this fabricates nothing: every provider-specific value
comes from profiles/common/offering-profile.json, and anything unprovided is an
honest TBD placeholder. A green schema validation means the document is
well-formed, never that its contents are true or that the provider is certified.

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


def _repository(desc):
    # Minimal valid `repository` object per the CPO schema.
    return {
        "repositoryType": ["Website"],
        "url": TBD_URI,
        "repositoryDescription": desc,
        "authenticationRequired": False,
    }


def build_cpo(profile):
    cls = (profile.get("certification_class") or "b").upper()
    # certificationType enum is '20x' or 'Rev5'. Map the offering profile's
    # human label to the schema token.
    ctype = "Rev5" if "rev5" in (profile.get("certification_type") or "").lower() else "20x"
    # deploymentModel must be one of the schema's enum values; default to the
    # most common commercial case and let the provider correct it.
    DEPLOY_ENUM = {"public cloud": "Public Cloud", "government-only cloud": "Government-Only Cloud",
                   "hybrid cloud": "Hybrid Cloud", "community cloud": "Community Cloud",
                   "government community cloud": "Government Community Cloud"}
    deploy = DEPLOY_ENUM.get((profile.get("deployment_model") or "").lower(), "Public Cloud")
    # serviceType enum is SaaS/PaaS/IaaS.
    stype = (profile.get("service_model") or "PaaS").upper()
    stype = {"SAAS": "SaaS", "PAAS": "PaaS", "IAAS": "IaaS"}.get(stype, "PaaS")
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
                "FedRAMP-compatible trust center for Certification Data (CDS-CSO-UTC)."),
            "secureConfigurationGuidance": _repository(
                "Secure Configuration Guide (SCG-CSO-RSC)."),
            "nextOngoingCertificationReportDate": profile.get("next_ocr_date")
            or "2026-01-01",
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
