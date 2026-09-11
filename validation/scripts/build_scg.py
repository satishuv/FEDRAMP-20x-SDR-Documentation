#!/usr/bin/env python3
"""Generate a Secure Configuration Guide (SCG) scaffold.

SCG-CSO-RSC requires providers to supply a Secure Configuration Guide covering
how to securely configure and use the service; SCG-CSO-AUP requires an
acceptable-use policy component. FedRAMP does not define a JSON schema for the
SCG (it is a human-readable guide, referenced from the CPO), so this generates
a Markdown scaffold with the required sections and honest TBD placeholders.

    python validation/scripts/build_scg.py

Output: package/scg/secure-configuration-guide.md
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_MD = os.path.join(BASE, "package", "scg", "secure-configuration-guide.md")

TBD = "TBD: the provider supplies this."


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def val(v):
    return v if v not in (None, "") else TBD


def render(profile):
    name = val(profile.get("offering_name"))
    acr = val(profile.get("offering_abbreviation"))
    L = []
    a = L.append
    a(f"# Secure Configuration Guide: {name} ({acr})")
    a("")
    a("This is a generated scaffold for the FedRAMP 20x Secure Configuration "
      "Guide required by SCG-CSO-RSC, with the acceptable-use component required "
      "by SCG-CSO-AUP. Sections marked TBD are filled by the provider. This "
      "document is referenced from the Certification Package Overview and is not "
      "a compliance claim.")
    a("")
    a("## Purpose and scope")
    a("")
    a(f"How to securely configure and operate {name}. Scope: {val(profile.get('business_purpose'))}")
    a("")
    a("## Secure configuration baseline (SCG-CSO-RSC)")
    a("")
    a("- Recommended secure settings customers must apply: " + TBD)
    a("- Default settings and which are secure out of the box: " + TBD)
    a("- Hardening steps and their rationale: " + TBD)
    a(f"- Infrastructure-as-code baseline, if provided ({val(profile.get('iac_technology'))}): " + TBD)
    a("")
    a("## Customer responsibilities")
    a("")
    a("- Configuration the customer owns versus the provider: " + TBD)
    a("- Identity, access, and key management expectations: " + TBD)
    a("")
    a("## Acceptable use policy (SCG-CSO-AUP)")
    a("")
    a("- Permitted and prohibited uses of the service: " + TBD)
    a("- Consequences of misuse and reporting channel: " + TBD)
    a("")
    a("## Change and version history")
    a("")
    a("- Guide version and last-updated date: " + TBD)
    a("- How configuration guidance changes are communicated: " + TBD)
    a("")
    a("---")
    a("")
    a("Generated scaffold. Every TBD must be replaced with the provider's real "
      "guidance and reviewed by a qualified human before use. A generated "
      "document is not a compliance determination.")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no SCG is generated.")
        return 1
    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(profile))
    print(f"SCG written: {os.path.relpath(OUT_MD, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
