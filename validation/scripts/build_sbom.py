#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for this framework's own directly-pinned dependencies.

A tool that asks providers to evidence their supply chain should model its own.
This emits a deterministic (no timestamps, sorted) CycloneDX 1.5 JSON SBOM from
the DIRECTLY-PINNED (`name==version`) entries in the requirements files, so a
consumer can see the exact top-level components the framework declares, and
verify them against the release manifest (which fingerprints this SBOM).

Scope, stated honestly: this lists the top-level dependencies the framework
pins directly (`==`). Their transitive dependencies are pinned INDIRECTLY (they
resolve to whatever the top-level pins allow) and are NOT enumerated here. A
fully-resolved closure with per-package hashes would require a committed lock
file produced by a resolver (pip-compile or uv); that is a separate
supply-chain-tooling change, tracked as follow-up. Until then this SBOM must not
be read as the complete resolved dependency set.

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
LOCK = os.path.join(BASE, "requirements.lock")
OUT = os.path.join(BASE, "artifacts", "sbom.cdx.json")

PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._-]+)\s*$")
LOCK_PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._!+-]+)")
HASH_RE = re.compile(r"--hash=(sha256:[0-9a-f]+)")


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


def _parse_lock(path):
    """Parse a pip-compile / uv style requirements.lock: the fully-resolved
    closure (direct + transitive) with per-package --hash lines. Returns
    {name: (version, [hashes])} or None if there is no lock. This is what makes
    the SBOM a COMPLETE resolved set rather than top-level pins only."""
    if not os.path.exists(path):
        return None
    comps = {}
    name = ver = None
    hashes = []
    def flush():
        if name:
            comps[name.lower()] = (ver, sorted(hashes))
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "-e", "--index", "--extra-index",
                            "--find-links", "--pre", "--no-")):
            continue  # include/option directives, not packages or hashes
        m = LOCK_PIN_RE.match(line)
        if m:  # a new package line
            flush()
            name, ver, hashes = m.group(1), m.group(2), []
            hashes += HASH_RE.findall(line)
        else:  # a continuation line (usually a --hash=...)
            hashes += HASH_RE.findall(line)
    flush()
    return comps or None


def build():
    lock = _parse_lock(LOCK)
    if lock is not None:
        # Complete resolved closure with hashes: the SBOM is the full set.
        sbom_scope = "resolved-closure-with-hashes"
        transitive_included = "true"
        components = []
        for name in sorted(lock):
            ver, hashes = lock[name]
            comp = {
                "type": "library",
                "name": name,
                "version": ver,
                "purl": f"pkg:pypi/{name}@{ver}",
            }
            if hashes:
                comp["hashes"] = [
                    {"alg": "SHA-256", "content": h.split(":", 1)[1]}
                    for h in hashes if h.startswith("sha256:")
                ]
            components.append(comp)
    else:
        # No lock committed: honest top-level pins only (direct deps).
        sbom_scope = "direct-top-level-pins"
        transitive_included = "false"
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

    _locked = sbom_scope == "resolved-closure-with-hashes"
    _desc = ("Provider-side FedRAMP 20x Certification Package framework. This "
             "SBOM covers the framework's own "
             + ("FULLY-RESOLVED Python dependency closure (direct plus "
                "transitive) with per-package SHA-256 hashes, from the committed "
                "requirements.lock."
                if _locked else
                "DIRECTLY-PINNED top-level Python dependencies (no committed "
                "requirements.lock present, so the transitive closure is not "
                "enumerated).")
             + " It does not cover the provider's offering.")
    _note = ("Transitive dependencies ARE enumerated with hashes from the "
             "committed requirements.lock." if _locked else
             "Transitive dependencies are pinned indirectly by the top-level "
             "pins and are not enumerated. Commit a requirements.lock "
             "(pip-compile/uv, see the Makefile 'lock' target) to upgrade this "
             "SBOM to a fully-resolved hash-locked closure automatically.")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "fedramp-20x-sdr-framework",
                "description": _desc,
            },
            "properties": [
                {"name": "sbom:scope", "value": sbom_scope},
                {"name": "sbom:transitive-included", "value": transitive_included},
                {"name": "sbom:note", "value": _note},
            ],
            "note": ("Deterministic SBOM (no build timestamps; serial derived from "
                     "the component set). Fingerprinted in the release manifest. "
                     f"Scope: {sbom_scope}."),
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
