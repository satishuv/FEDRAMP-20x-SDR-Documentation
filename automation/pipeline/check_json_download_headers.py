#!/usr/bin/env python3
"""Deployment-hardening ADVISORY check for certification-JSON download headers.

FedRAMP Help Center guidance (September 15, 2026) RECOMMENDS that when
certification data JSON is served for download, the response carry:

    Content-Type: application/json
    X-Content-Type-Options: nosniff
    Content-Disposition: attachment

so the JSON is not interpreted as active content by a browser or a downstream
automated FedRAMP/agency system. This is GUIDANCE, not a Consolidated Rules
MUST: it is NOT in the pinned fedramp-consolidated-rules.json dataset, so it is
NEVER a submission blocker and NEVER a package-preflight gate. This script is a
deployment-hardening aid the provider runs against their OWN hosted
certification-JSON download endpoint.

Usage:
    # Evaluate a headers file (JSON object of header->value); advisory report:
    python automation/pipeline/check_json_download_headers.py --headers-file h.json
    # Or fetch a provider-hosted URL (advisory; requires network + urllib):
    python automation/pipeline/check_json_download_headers.py --url https://trust.example.gov/cert.json

Exit code is 0 unless --strict is passed AND a recommended header is absent;
by default a missing header is reported as an advisory and the exit stays 0,
matching the RECOMMENDED (not MUST) force.
"""

import argparse
import json
import sys

# (header, expected-substring-in-value, human label). The value check is a
# case-insensitive substring so "application/json; charset=utf-8" still matches.
RECOMMENDED_HEADERS = [
    ("content-type", "application/json", "Content-Type: application/json"),
    ("x-content-type-options", "nosniff", "X-Content-Type-Options: nosniff"),
    ("content-disposition", "attachment", "Content-Disposition: attachment"),
]


def evaluate_headers(headers):
    """Evaluate a response's headers against the RECOMMENDED set.

    headers: a mapping of header name -> value (any case). Returns a list of
    {header, label, present, value} dicts, one per recommended header. Pure and
    offline so it is unit-testable without a network.
    """
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    results = []
    for name, want, label in RECOMMENDED_HEADERS:
        val = lower.get(name)
        present = val is not None and want.lower() in val.lower()
        results.append({"header": name, "label": label,
                        "present": present, "value": val})
    return results


def _report(results, strict):
    missing = [r for r in results if not r["present"]]
    for r in results:
        mark = "PASS" if r["present"] else ("FAIL" if strict else "ADVISORY")
        got = f" (got: {r['value']})" if r["value"] is not None else " (header absent)"
        print(f"  {mark} {r['label']}{got}")
    if missing:
        print(f"\n{len(missing)} recommended header(s) not confirmed. This is "
              "FedRAMP GUIDANCE (RECOMMENDED), not a Consolidated Rules MUST, so "
              "it is advisory only and never a submission blocker.")
    else:
        print("\nAll recommended certification-JSON download headers present.")
    return 1 if (strict and missing) else 0


def _fetch_headers(url):
    import urllib.request
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        return dict(resp.headers.items())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--headers-file", help="JSON file: object of header->value")
    src.add_argument("--url", help="fetch this URL and evaluate its headers "
                                   "(advisory; needs network access)")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if a recommended header is absent "
                         "(off by default: the guidance is RECOMMENDED)")
    args = ap.parse_args(argv)

    print("Certification-JSON download-header check (FedRAMP RECOMMENDED "
          "guidance, 2026-09-15; advisory, not a Consolidated Rules MUST)")
    print("-" * 68)
    if args.headers_file:
        with open(args.headers_file, encoding="utf-8") as f:
            headers = json.load(f)
    else:
        try:
            headers = _fetch_headers(args.url)
        except Exception as exc:  # noqa: BLE001
            print(f"  Could not fetch {args.url}: {exc}")
            print("  (advisory check could not run; not a blocker)")
            return 0
    return _report(evaluate_headers(headers), args.strict)


if __name__ == "__main__":
    sys.exit(main())
