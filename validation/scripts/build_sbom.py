#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for this framework's own pinned dependencies.

A tool that asks providers to evidence their supply chain should model its own.
This emits a deterministic (no timestamps, sorted) CycloneDX 1.5 JSON SBOM from
the pinned requirements files, so a consumer can see exactly which components and
exact versions the framework runs on, and verify them against the release
manifest (which fingerprints this SBOM).

    python validation/scripts/build_sbom.py

Deterministic by construction: the serial number is derived from a hash of the
component set, not a random UUID, so an unchanged dependency set yields a
byte-identical SBOM (compatible with the reproducibility gate).
"""

import hashlib
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REQ = os.path.join(BASE, "requirements.txt")
REQ_CI = os.path.join(BASE, "requirements-ci.txt")
OUT = os.path.join(BASE, "artifacts", "sbom.cdx.json")

PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._-]+)\s*$")


def _parse(path, scope):
    """Return {name: (version, scope)} for exact-pinned lines in a requirements
    file. Non-pin lines (comments, -r includes, unpinned) are ignored here; the
    pinned set is what the SBOM asserts."""
    comps = {}
    if not os.path.exists(path):
        return comps
    for line in open(path, encoding="utf-8"):
        m = PIN_RE.match(line.strip())
        if m:
            comps[m.group(1).lower()] = (m.group(2), scope)
    return comps


def build():
    # Runtime deps are "required"; CI-only deps are "optional" (test/build).
    comps = _parse(REQ, "required")
    for name, (ver, _s) in _parse(REQ_CI, "optional").items():
        comps.setdefault(name, (ver, "optional"))

    components = []
    for name in sorted(comps):
        ver, scope = comps[name]
        components.append({
            "type": "library",
            "name": name,
            "version": ver,
            "scope": "required" if scope == "required" else "optional",
            "purl": f"pkg:pypi/{name}@{ver}",
        })

    # Deterministic serial: hash of the component set (name@version), so an
    # unchanged dependency set is byte-identical across builds.
    digest = hashlib.sha256(
        "|".join(f"{c['name']}@{c['version']}" for c in components).encode()
    ).hexdigest()
    serial = f"urn:uuid:{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "fedramp-20x-sdr-framework",
                "description": ("Provider-side FedRAMP 20x Certification Package "
                                "framework. SBOM covers the framework's own pinned "
                                "Python dependencies, not the provider's offering."),
            },
            "note": ("Deterministic SBOM (no build timestamps; serial derived from "
                     "the component set). Fingerprinted in the release manifest."),
        },
        "components": components,
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(sbom, f, indent=1)
        f.write("\n")
    print(f"SBOM written: {os.path.relpath(OUT, BASE)} ({len(components)} components).")
    return 0


if __name__ == "__main__":
    sys.exit(build())
