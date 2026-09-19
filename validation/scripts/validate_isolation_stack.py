#!/usr/bin/env python3
"""Lint the evidence-store isolation reference stack for its load-bearing
invariants. This does NOT deploy - it asserts the reference CloudFormation
template still encodes the four properties that make the isolation meaningful:

  1. The evidence bucket has Object Lock ENABLED (write-once).
  2. The bucket policy DENIES the assessed collector roles bucket mutations.
  3. The signing key DENIES the assessed collector roles kms:Sign.
  4. The signing key grants kms:Sign to a SEPARATE signer principal.

A regression that silently drops any of these (e.g. removing the deny) would
hollow out the chain of custody, so CI checks the invariants hold. Parsed as
plain YAML text (no cfn-lint dependency); the checks are substring/structure
assertions robust to formatting.

    python validation/scripts/validate_isolation_stack.py

Exit 1 if any invariant is missing.
"""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATE = os.path.join(BASE, "automation", "evidence-store-isolation",
                        "cloudformation.yaml")


def main():
    try:
        with open(TEMPLATE, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(f"FAIL: cannot read {TEMPLATE}: {e}")
        return 1

    checks = [
        ("evidence bucket has Object Lock enabled",
         "ObjectLockEnabled: true" in text and "ObjectLockConfiguration:" in text),
        ("Object Lock uses COMPLIANCE mode (write-once, not shortenable)",
         "Mode: COMPLIANCE" in text),
        ("bucket policy denies assessed collector mutations",
         "DenyAssessedCollectorMutations" in text
         and "Effect: Deny" in text
         and "s3:DeleteObject" in text),
        ("signing key denies assessed collectors kms:Sign",
         "DenyAssessedCollectorsSign" in text and "kms:Sign" in text),
        ("signing key grants kms:Sign to a separate signer principal",
         "AllowSignerToSign" in text and "SignerPrincipalArn" in text),
        ("signing key is asymmetric SIGN_VERIFY",
         "KeyUsage: SIGN_VERIFY" in text and "ECC_NIST_P256" in text),
        ("evidence access is logged to a separate bucket",
         "LoggingConfiguration:" in text and "EvidenceLogBucket" in text),
        ("assessed collectors cannot bypass governance retention",
         "s3:BypassGovernanceRetention" in text),
    ]

    print("Evidence-store isolation reference-stack gate")
    print("-" * 68)
    failed = []
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'} {name}")
        if not ok:
            failed.append(name)
    if failed:
        print(f"\nHARD failures ({len(failed)}): the reference stack lost a "
              "load-bearing isolation invariant.")
        return 1
    print("\nPASS: the isolation reference stack encodes every load-bearing "
          "invariant (WORM, deny-collector-mutation, deny-collector-sign, "
          "separate signer, separate access logging).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
