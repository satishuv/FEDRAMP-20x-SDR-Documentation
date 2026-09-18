# Adversarial tests for FRC-CLA-ASF / FRC-CLA-EAM Class A framework handling.
#
# Two defects fixed and locked here:
#   1. A bare "SOC 2" / "soc2" must NOT be treated as SOC 2 Type II (a Type I is
#      not eligible under FRC-CLA-ASF).
#   2. FedRAMP Rev5 (full authorization) must NOT inherit FedRAMP Ready's
#      Readiness Assessment Report + Security Assessment Plan material set; EAM
#      assigns those to FedRAMP Ready, and Rev5 has no fixed EAM type list.
#
# Run: python validation/scripts/test_class_a_framework.py

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def main():
    k = sdr.class_a_framework_key

    # SOC 2 Type II specificity.
    check("'SOC 2 Type II' -> soc2_type_ii", k("SOC 2 Type II") == "soc2_type_ii")
    check("'soc2_type_ii' -> soc2_type_ii", k("soc2_type_ii") == "soc2_type_ii")
    check("bare 'SOC 2' is NOT approved", k("SOC 2") is None)
    check("bare 'soc2' is NOT approved", k("soc2") is None)
    check("'SOC 2 Type I' is NOT approved", k("SOC 2 Type I") is None)

    # Rev5 vs Ready are distinct canonical keys.
    check("'FedRAMP Rev5' -> fedramp_rev5", k("FedRAMP Rev5") == "fedramp_rev5")
    check("'rev5' -> fedramp_rev5", k("rev5") == "fedramp_rev5")
    check("'FedRAMP Ready' -> fedramp_ready", k("FedRAMP Ready") == "fedramp_ready")
    check("'GovRAMP' -> govramp", k("GovRAMP") == "govramp")
    check("unknown framework -> None", k("ISO 27001") is None)
    check("None -> None", k(None) is None)

    # Required-material sets: Rev5 must NOT carry Ready's RAR/SAP.
    rev5 = sdr.class_a_required_material_types("fedramp_rev5")
    ready = sdr.class_a_required_material_types("fedramp_ready")
    soc2 = sdr.class_a_required_material_types("soc2_type_ii")
    check("Rev5 has NO fixed EAM material types", rev5 == [])
    check("Ready requires RAR + SAP",
          set(ready) == {"readiness_assessment_report", "security_assessment_plan"})
    check("Rev5 does not inherit Ready's RAR/SAP",
          "readiness_assessment_report" not in rev5 and "security_assessment_plan" not in rev5)
    check("SOC 2 Type II requires complete_report + audit engagement + schedule",
          set(soc2) == {"complete_report", "verified_audit_engagement",
                        "upcoming_report_schedule"})

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: class A framework ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
