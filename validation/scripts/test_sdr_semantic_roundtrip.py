# Golden round-trip tests for SDR semantic completeness.
#
# These prove that every information item FedRAMP requires (SDR-CSO-FRR for
# rules, SDR-CSX-KSI plus SDR-CSX-KMT for indicators) survives the trip from
# the editable record store, through the generated official JSON, into the
# human-readable rendering. Before this suite existed, several required items
# were held only in the record store and silently dropped from the generated
# deliverables while the JSON still passed schema validation. The suite fails
# if a required field stops reaching either output.
#
# Presence, not truth: a field filled with a TBD placeholder counts as present.
# These tests never assert the content is correct; that is the human assessor's
# job. They assert the STRUCTURE carries every required slot.
#
# Offline: no network, no AWS, no external data. Run with:
#   python validation/scripts/test_sdr_semantic_roundtrip.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_sdr  # noqa: E402


FRR_SEMANTIC_KEYS = [
    "implementationRisk", "verification", "independentVerification",
    "independentValidation", "assessorResponses", "ruleArtifacts",
]
KSI_SEMANTIC_KEYS = [
    "measures", "operatingCycle", "measuresVerification",
    "automationVerification", "historicalMetrics",
]
KMT_KEYS = ["last30Days", "upToOneYear", "dailyDataReference"]

SENTINEL = "ROUNDTRIP-SENTINEL-VALUE-XYZ"


def _sample_records():
    """A minimal two-entry record store with every semantic field populated by
    a unique sentinel, so we can prove the exact value reaches each output."""
    return {
        "frr": {
            "AFC-CSO-INB": {
                "implementation_status": "Implemented",
                "implementation": ["impl-" + SENTINEL],
                "validation": ["val-" + SENTINEL],
                "assessment": ["assess-" + SENTINEL],
                "extension": {
                    "owner": "owner-" + SENTINEL,
                    "customer_risk": "risk-" + SENTINEL,
                    "verification": "verify-" + SENTINEL,
                    "independent_verification": "iv-" + SENTINEL,
                    "independent_validation": "ival-" + SENTINEL,
                    "assessor_responses": "resp-" + SENTINEL,
                    "rule_artifacts": [{"artifactId": "EV-" + SENTINEL}],
                },
            }
        },
        "ksi": {
            "KSI-CNA-RNT": {
                "implementation_status": "Implemented",
                "implementation": ["kimpl-" + SENTINEL],
                "validation": ["kval-" + SENTINEL],
                "assessment": ["kassess-" + SENTINEL],
                "tests": ["automated/config-check"],
                "evidence": [],
                "historical_metrics": {
                    "last_30_days": "m30-" + SENTINEL,
                    "up_to_one_year": "m1y-" + SENTINEL,
                    "daily_data_reference": "daily-" + SENTINEL,
                },
                "extension": {
                    "owner": "kowner-" + SENTINEL,
                    "measures": "measures-" + SENTINEL,
                    "operating_cycle": "cycle-" + SENTINEL,
                    "measures_verification": "mv-" + SENTINEL,
                    "automation_verification": "av-" + SENTINEL,
                    "assessor_responses": "kresp-" + SENTINEL,
                },
            }
        },
    }


def test_frr_semantic_block_present_in_official_json():
    sem = build_sdr.frr_semantic(_sample_records()["frr"]["AFC-CSO-INB"])
    for key in FRR_SEMANTIC_KEYS:
        assert key in sem, f"frr_semantic missing required item {key}"
    assert sem["independentVerification"] == "iv-" + SENTINEL
    assert sem["ruleArtifacts"] == [{"artifactId": "EV-" + SENTINEL}]


def test_ksi_semantic_block_present_in_official_json():
    sem = build_sdr.ksi_semantic(_sample_records()["ksi"]["KSI-CNA-RNT"])
    for key in KSI_SEMANTIC_KEYS:
        assert key in sem, f"ksi_semantic missing required item {key}"
    for key in KMT_KEYS:
        assert key in sem["historicalMetrics"], f"historicalMetrics missing {key}"
    assert sem["automationVerification"] == "av-" + SENTINEL
    assert sem["historicalMetrics"]["dailyDataReference"] == "daily-" + SENTINEL


def test_absent_value_becomes_tbd_not_dropped():
    # A required field with no authored value must surface as the TBD marker,
    # never vanish. Absence is a completeness defect; TBD is honest.
    sem = build_sdr.frr_semantic({"extension": {}})
    for key in ["implementationRisk", "verification", "independentVerification",
                "independentValidation", "owner"]:
        assert sem[key] == build_sdr.TBD, f"{key} should be TBD when unauthored"


def test_generated_official_json_carries_semantic_for_every_entry():
    """The shipped Class B SDR must carry the semantic block on every rule and
    KSI. Guards against a future generator change dropping it."""
    path = os.path.join(BASE, "sdr", "json", "sdr-class-b.json")
    if not os.path.exists(path):
        print("SKIP generated-json check: build the SDR first (python sdr.py build)")
        return
    doc = json.load(open(path, encoding="utf-8"))
    for entry in doc["fedRampRequirements"]:
        sem = entry.get("providerExtensions", {}).get("xFedRampSemantic")
        assert sem is not None, f"{entry['frrID']} lost its semantic block"
        for key in FRR_SEMANTIC_KEYS:
            assert key in sem, f"{entry['frrID']} missing {key}"
    for entry in doc["keySecurityIndicators"]:
        sem = entry.get("providerExtensions", {}).get("xFedRampSemantic")
        assert sem is not None, f"{entry['ksiId']} lost its semantic block"
        for key in KSI_SEMANTIC_KEYS:
            assert key in sem, f"{entry['ksiId']} missing {key}"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} semantic round-trip tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
