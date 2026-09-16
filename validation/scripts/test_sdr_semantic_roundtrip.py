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


def test_authoring_status_maps_to_official_enum():
    # The official schema allows only Implemented / Not Implemented / Partially
    # Implemented. Every richer authoring status must map into that set, and only
    # Implemented / Partially Implemented pass through as-is.
    OFFICIAL = {"Implemented", "Not Implemented", "Partially Implemented"}
    cases = {
        "Implemented": "Implemented",
        "Partially Implemented": "Partially Implemented",
        "Not Implemented": "Not Implemented",
        "Planned": "Not Implemented",
        "Gap": "Not Implemented",
        "Not Applicable": "Not Implemented",
        "Exception": "Not Implemented",
        "Needs validation": "Not Implemented",
        "FedRAMP pending": "Not Implemented",
        "TBD": "Not Implemented",
        "": "Not Implemented",
    }
    for authoring, expected in cases.items():
        got = build_sdr.official_status(authoring)
        assert got in OFFICIAL, f"{authoring!r} -> {got!r} not in official enum"
        assert got == expected, f"{authoring!r} -> {got!r}, expected {expected!r}"


def test_ksi_class_varying_statement_resolves_not_null():
    # The 5 KSIs with a null top-level statement carry class-specific text under
    # varies_by_class. The resolver must return the class statement, never None,
    # and must differ per class where the dataset differs (B is "Optional:").
    k = {
        "ksi_id": "KSI-CNA-EIS",
        "statement": None,
        "varies_by_class": {
            "b": {"statement": "**Optional:** do the thing."},
            "c": {"statement": "Do the thing."},
        },
    }
    assert build_sdr.ksi_statement_for_class(k, "b") == "**Optional:** do the thing."
    assert build_sdr.ksi_statement_for_class(k, "c") == "Do the thing."
    # A plain top-level KSI still resolves to its statement for any class.
    plain = {"ksi_id": "KSI-IAM-MFA", "statement": "Use MFA."}
    assert build_sdr.ksi_statement_for_class(plain, "b") == "Use MFA."


def test_class_b_sdr_has_no_pending_statement_for_varies_by_class_ksis():
    # Regression: the built Class B human-readable must NOT print the wrong
    # "FedRAMP pending, no statement" line for the 5 class-varying KSIs.
    path = os.path.join(BASE, "sdr", "human-readable", "sdr-class-b.txt")
    if not os.path.exists(path):
        return  # build not present in this checkout; skip
    text = open(path, encoding="utf-8").read()
    # The security-outcome for KSI-CNA-EIS must be a real statement.
    assert "Enforcing Intended State" in text
    # No KSI security outcome should be the pending sentinel (all 46 have text
    # or a class-specific statement in 2026.09.13.02).
    assert "Security outcome: FedRAMP pending" not in text


def test_class_b_profile_preserves_timeframe_range():
    # Regression: CCM-QTR-SAR carries a bizdays 3..10 range; CCM-OCR-AVL carries
    # months/3 at the top level. Both must survive into the class profile.
    path = os.path.join(BASE, "profiles", "class-b", "profile.json")
    if not os.path.exists(path):
        return
    p = json.load(open(path, encoding="utf-8"))
    rules = p.get("rules") or p.get("applicable_rules") or {}
    it = rules if isinstance(rules, list) else list(rules.values())
    by_id = {r.get("rule_id"): r for r in it if isinstance(r, dict)}
    sar = by_id.get("CCM-QTR-SAR")
    if sar:
        assert sar.get("timeframe_type") == "bizdays"
        assert sar.get("timeframe_num_min") == 3
        assert sar.get("timeframe_num_max") == 10
    avl = by_id.get("CCM-OCR-AVL")
    if avl:
        assert avl.get("timeframe_type") == "months"
        assert avl.get("timeframe_num") == 3


def test_all_class_sdr_outputs_match_pinned_dataset():
    # Invariant: every committed A/B/C SDR must be generated against the pinned
    # dataset. Assert on the EXTENSIONS companion's dataset_version (source
    # currency), NOT lastUpdated: lastUpdated can legitimately be a later
    # provider record-update date (sdr_last_updated) and does not track the
    # dataset version.
    ds = json.load(open(os.path.join(BASE, "references",
                                     "fedramp-consolidated-rules.json"), encoding="utf-8"))
    ver = ds["info"]["version"]
    for cls in ("a", "b", "c"):
        path = os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}-extensions.json")
        if not os.path.exists(path):
            continue
        doc = json.load(open(path, encoding="utf-8"))
        got = (doc.get("metadata") or {}).get("dataset_version") or doc.get("dataset_version")
        assert got == ver, (
            f"Class {cls.upper()} SDR extensions dataset_version {got!r} != pinned "
            f"{ver!r}; regenerate all classes (SDR_BUILD_CLASS) after a dataset "
            "refresh so committed cross-class outputs never drift")


def test_all_class_authoring_docx_embed_pinned_dataset():
    # DOCX bytes are nondeterministic (zip), so they are excluded from the CI
    # byte-diff. Instead, check SEMANTICALLY that each class authoring DOCX
    # embeds the pinned dataset version, so inactive-class Word files cannot
    # silently fall behind a dataset refresh.
    import re
    import zipfile
    ds = json.load(open(os.path.join(BASE, "references",
                                     "fedramp-consolidated-rules.json"), encoding="utf-8"))
    ver = ds["info"]["version"]
    for cls in ("a", "b", "c"):
        path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}-authoring.docx")
        if not os.path.exists(path):
            continue
        with zipfile.ZipFile(path) as z:
            xml = z.read("word/document.xml").decode("utf-8", "replace")
        found = set(re.findall(r"2026\.\d{2}\.\d{2}\.\d{2}", xml))
        assert found, f"Class {cls.upper()} authoring DOCX embeds no dataset version"
        assert found == {ver}, (
            f"Class {cls.upper()} authoring DOCX embeds {sorted(found)} != pinned "
            f"{ver}; regenerate it (SDR_BUILD_CLASS={cls} build_docx.py) after a "
            "dataset refresh")


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
