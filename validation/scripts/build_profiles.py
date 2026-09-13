# Build Class B and Class C certification profiles from the derived catalogs.
# Filters the rule catalog to provider-affecting rules and resolves per-class
# applicability using the varies_by_class model documented in the fedramp-20x skill:
# a rule with no class variant applies per its top-level statement; a rule with
# variants applies to a class only as that class's variant states.
#
# Outputs:
#   profiles/class-b/profile.json          - full resolved Class B rule set
#   profiles/class-c/profile.json          - full resolved Class C rule set
#   profiles/class-c/overlay.json          - only what differs from Class B
#   profiles/common/ksi-profile.json       - all 46 KSIs with per-class validation minimums
#
# Deterministic. Re-run after every catalog rebuild.

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(BASE, "traceability", "rule-catalog.json")
KSI_CATALOG = os.path.join(BASE, "traceability", "ksi-catalog.json")
PROFILES = os.path.join(BASE, "profiles")
CANONICAL = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")

# FRC-CSX-VVK: minimum automated verification/validation methods per KSI.
from fedramp_constants import VVK_MINIMUM

# Subsets that are scoped to a single class by their statement text rather than
# a varies_by_class block. CLA rules apply only to providers seeking Class A
# (verified: FRC-CLA-ASF, FRC-CLA-EAM, FRC-CLA-MFR, FRC-CLA-IVV all state
# "Providers seeking a FedRAMP Class A Certification MUST ..."), so they are
# excluded from the Class B and Class C profiles.
CLASS_A_ONLY_SUBSETS = {"CLA"}

# SDR-CSX-KMT: historical metric obligations per class.
METRICS = {
    "a": "Optional under SDR-CSX-KMT: Class A providers MAY include historical metrics; none are required.",
    "b": "Summary of each metric over the past 30 days, and up to the past year where available.",
    "c": "Class B summaries plus all daily metric data up to the past year where available.",
    "d": "FedRAMP pending: must significantly supersede lower classes; specifics set during the 20x Phase 4 Pilot.",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_family_names():
    path = os.path.join(BASE, "traceability", "family-names.json")
    if os.path.exists(path):
        return load(path)
    return {"frr": {}, "ksi": {}}


FAMILY_NAMES = load_family_names()


def fam_full(code):
    return FAMILY_NAMES["frr"].get(code, code)


def affects_providers(rule):
    aff = rule.get("affects") or []
    return "Providers" in aff


# This framework targets 20x Program Certification. Subset-level
# applicability metadata (types/paths/classes) in the canonical dataset
# governs; e.g. FRC APS and CCL subsets are Rev5/Agency only and must be
# excluded even though their rules affect Providers.
TARGET_TYPE = "20x"
TARGET_PATH = "Program"


def subset_applies(rule, cls, skip_class_check=False):
    app = rule.get("subset_applicability")
    if not app:
        return True, None
    types = app.get("types")
    if types and TARGET_TYPE not in types:
        return False, f"subset types {types} exclude {TARGET_TYPE}"
    paths = app.get("paths")
    if paths and TARGET_PATH not in paths:
        return False, f"subset paths {paths} exclude {TARGET_PATH}"
    if not skip_class_check:
        classes = app.get("classes")
        if classes and cls.upper() not in [c.upper() for c in classes]:
            return False, f"subset classes {classes} exclude {cls.upper()}"
    return True, None


def resolve_for_class(rule, cls):
    """Return the resolved statement/force for a class, or None if the rule
    does not apply to that class."""
    vbc = rule.get("varies_by_class")
    if vbc:
        variant = vbc.get(cls)
        if variant and variant.get("statement"):
            return {
                "statement": variant["statement"],
                "force": variant.get("force"),
                "timeframe_type": variant.get("timeframe_type"),
                "timeframe_num": variant.get("timeframe_num"),
                "resolution": "class_variant",
            }
        if rule.get("statement"):
            return {
                "statement": rule["statement"],
                "force": rule.get("force"),
                "resolution": "top_level_with_other_class_variants",
            }
        return None
    if rule.get("statement"):
        return {
            "statement": rule["statement"],
            "force": rule.get("force"),
            "resolution": "top_level",
        }
    return None


def get_class_a_lists():
    """Class A applicability is enumerated, not blanket. FRC-CLA-MFR lists the
    mandatory rules and KSIs, FRC-CLA-RFR the recommended rules, FRC-CLA-OFR
    the optional rules. Parse those lists from the canonical dataset so the
    profile always tracks the official text."""
    import re
    with open(CANONICAL, encoding="utf-8") as f:
        d = json.load(f)
    cla = d["FRR"]["FRC"]["data"]["all"]["CLA"]
    rule_pat = re.compile(r"\b([A-Z]{3}-[A-Z]{3}-[A-Z]{3})\b")
    ksi_pat = re.compile(r"\b(KSI-[A-Z]{3}-[A-Z]{3})\b")
    tiers = {"FRC-CLA-MFR": "mandatory", "FRC-CLA-RFR": "recommended",
             "FRC-CLA-OFR": "optional"}
    frr_tier, ksi_tier = {}, {}
    for code, tier in tiers.items():
        items = cla[code].get("following_information") or []
        for item in items:
            text = item if isinstance(item, str) else json.dumps(item)
            for m in ksi_pat.findall(text):
                ksi_tier[m] = tier
            for m in rule_pat.findall(text):
                if not m.startswith("KSI"):
                    frr_tier[m] = tier
    # remove KSI ids accidentally caught by the generic rule pattern
    frr_tier = {k: v for k, v in frr_tier.items() if k not in ksi_tier}
    return frr_tier, ksi_tier


def build_class_a_profile(rules, frr_tier, excluded_log=None):
    """Class A profile: all 6 FRC CLA subset rules (mandatory) plus exactly the
    rules enumerated by FRC-CLA-MFR/RFR/OFR, each resolved for class a."""
    entries = []
    by_id = {r["rule_id"]: r for r in rules}
    wanted = dict(frr_tier)
    for rule in rules:
        if rule.get("subset") in CLASS_A_ONLY_SUBSETS:
            wanted[rule["rule_id"]] = "mandatory"
    missing = []
    for rule_id, tier in sorted(wanted.items()):
        rule = by_id.get(rule_id)
        if rule is None:
            missing.append(rule_id)
            continue
        # The FRC-CLA enumeration is the specific governing text for Class A,
        # so it overrides the subsets' general class metadata (which lists
        # B/C/D because Class A only follows the enumerated picks). Types and
        # paths still apply: a Rev5-only rule stays out of a 20x Program
        # profile even when RFR lists it "if applicable".
        ok, reason = subset_applies(rule, "a", skip_class_check=True)
        if not ok:
            if excluded_log is not None:
                excluded_log.append(
                    {"rule_id": rule_id, "family": rule["family"],
                     "subset": rule["subset"], "reason": reason}
                )
            continue
        resolved = resolve_for_class(rule, "a")
        if resolved is None:
            if excluded_log is not None:
                excluded_log.append(
                    {"rule_id": rule_id, "family": rule["family"],
                     "subset": rule["subset"],
                     "reason": (
                         "no statement resolvable for class A: "
                         "varies_by_class defines "
                         + "/".join(sorted((rule.get("varies_by_class") or {}).keys()))
                         + " only and there is no top-level statement"
                     )}
                )
            continue
        entries.append(
            {
                "rule_id": rule["rule_id"],
                "family": rule["family"],
                "family_name": fam_full(rule["family"]),
                "subset": rule["subset"],
                "name": rule["name"],
                "class_a_obligation": tier,
                "force": resolved.get("force"),
                "statement": resolved["statement"],
                "timeframe_type": resolved.get("timeframe_type"),
                "timeframe_num": resolved.get("timeframe_num"),
                "resolution": resolved["resolution"],
                "schema": rule.get("schema"),
            }
        )
    return entries, missing


def build_class_profile(rules, cls, excluded_log=None):
    entries = []
    for rule in rules:
        if cls in ("b", "c", "d") and rule.get("subset") in CLASS_A_ONLY_SUBSETS:
            continue
        ok, reason = subset_applies(rule, cls)
        if not ok:
            if excluded_log is not None:
                excluded_log.append(
                    {"rule_id": rule["rule_id"], "family": rule["family"],
                     "subset": rule["subset"], "reason": reason}
                )
            continue
        resolved = resolve_for_class(rule, cls)
        if resolved is None:
            # A rule with class variants but no variant for this class and no
            # top-level statement has no defined text at this class. Log it
            # like every other exclusion so a dataset update can never shrink
            # a profile silently.
            if excluded_log is not None:
                excluded_log.append(
                    {"rule_id": rule["rule_id"], "family": rule["family"],
                     "subset": rule["subset"],
                     "reason": (
                         f"no statement resolvable for class {cls.upper()}: "
                         "varies_by_class defines "
                         + "/".join(sorted((rule.get("varies_by_class") or {}).keys()))
                         + " only and there is no top-level statement"
                     )}
                )
            continue
        entries.append(
            {
                "rule_id": rule["rule_id"],
                "family": rule["family"],
                "family_name": fam_full(rule["family"]),
                "subset": rule["subset"],
                "name": rule["name"],
                "force": resolved.get("force"),
                "statement": resolved["statement"],
                "timeframe_type": resolved.get("timeframe_type"),
                "timeframe_num": resolved.get("timeframe_num"),
                "resolution": resolved["resolution"],
                "schema": rule.get("schema"),
            }
        )
    return entries


def build_overlay(profile_b, profile_c):
    by_id_b = {e["rule_id"]: e for e in profile_b}
    overlay = {"added": [], "changed": []}
    for entry in profile_c:
        prior = by_id_b.get(entry["rule_id"])
        if prior is None:
            overlay["added"].append(entry)
        elif (
            prior["statement"] != entry["statement"]
            or prior["force"] != entry["force"]
            or prior.get("timeframe_num") != entry.get("timeframe_num")
        ):
            overlay["changed"].append(
                {
                    "rule_id": entry["rule_id"],
                    "name": entry["name"],
                    "class_b": {
                        "force": prior["force"],
                        "statement": prior["statement"],
                        "timeframe_num": prior.get("timeframe_num"),
                        "timeframe_type": prior.get("timeframe_type"),
                    },
                    "class_c": {
                        "force": entry["force"],
                        "statement": entry["statement"],
                        "timeframe_num": entry.get("timeframe_num"),
                        "timeframe_type": entry.get("timeframe_type"),
                    },
                }
            )
    ids_c = {e["rule_id"] for e in profile_c}
    overlay["removed"] = [
        {"rule_id": e["rule_id"], "name": e["name"]}
        for e in profile_b
        if e["rule_id"] not in ids_c
    ]
    return overlay


def build_ksi_profile(ksis, ksi_tier=None):
    ksi_tier = ksi_tier or {}
    entries = []
    for k in ksis:
        entries.append(
            {
                "ksi_id": k["ksi_id"],
                "class_a_obligation": ksi_tier.get(
                    k["ksi_id"], "not required for Class A"),
                "family": k["family"],
                "family_name": k["family_name"],
                "name": k["name"],
                "statement": k["statement"],
                "controls": k["controls"],
                "content_status": (
                    "FedRAMP pending: statement empty in official dataset"
                    if k["status_note"] != "ok"
                    else "stable"
                ),
                "minimum_automated_methods": {
                    "class_a": VVK_MINIMUM["a"],
                    "class_b": VVK_MINIMUM["b"],
                    "class_c": VVK_MINIMUM["c"],
                    "class_d_future": VVK_MINIMUM["d"],
                },
                "historical_metrics": {
                    "class_a": METRICS["a"],
                    "class_b": METRICS["b"],
                    "class_c": METRICS["c"],
                    "class_d_future": METRICS["d"],
                },
            }
        )
    return entries


def build_class_d_register(provider_rules, profile_c, excluded_log=None):
    """Future-readiness register for Class D. The 20x Program path for
    Class D is listed by FedRAMP as coming in 2027 and Class D specifics
    are set during the Phase 4 pilot, so this is a readiness view only:
    the rules that would apply, resolved for class d where the dataset
    already carries a d variant, with a delta against Class C so a
    Class C provider can see exactly what tightens."""
    profile_d = build_class_profile(provider_rules, "d", excluded_log)
    by_id_c = {e["rule_id"]: e for e in profile_c}
    delta = []
    for entry in profile_d:
        c_entry = by_id_c.get(entry["rule_id"])
        if c_entry is None:
            delta.append({"rule_id": entry["rule_id"], "change": "added_at_d",
                          "force": entry.get("force")})
        elif (entry.get("statement") != c_entry.get("statement")
              or entry.get("force") != c_entry.get("force")):
            delta.append(
                {
                    "rule_id": entry["rule_id"],
                    "change": "differs_from_c",
                    "force_c": c_entry.get("force"),
                    "force_d": entry.get("force"),
                    "timeframe_c": [c_entry.get("timeframe_num"),
                                    c_entry.get("timeframe_type")],
                    "timeframe_d": [entry.get("timeframe_num"),
                                    entry.get("timeframe_type")],
                    "statement_d": entry.get("statement"),
                }
            )
    d_ids = {e["rule_id"] for e in profile_d}
    by_id_rules = {r["rule_id"]: r for r in provider_rules}
    for entry in profile_c:
        rule_id = entry["rule_id"]
        if rule_id in d_ids:
            continue
        rule = by_id_rules.get(rule_id, {})
        vbc = rule.get("varies_by_class") or {}
        if vbc and "d" not in vbc and not rule.get("statement"):
            delta.append(
                {
                    "rule_id": rule_id,
                    "change": "fedramp_pending_at_d",
                    "note": (
                        "The canonical dataset defines class variants for "
                        + "/".join(sorted(vbc.keys()))
                        + " only; no class d text exists yet. Class D "
                        "specifics are set during the 20x Phase 4 Pilot."
                    ),
                }
            )
        else:
            delta.append({"rule_id": rule_id, "change": "not_present_at_d"})
    return profile_d, delta


def main():
    catalog = load(CATALOG)
    ksi_catalog = load(KSI_CATALOG)
    meta = {
        "derived_from": "rule-catalog.json / ksi-catalog.json",
        "dataset_version": catalog["meta"]["dataset_version"],
        "generated": f"deterministic build from dataset {catalog['meta']['dataset_version']}",
        "path": "FedRAMP 20x Program Certification",
        "filter": "rules whose affects includes Providers",
    }

    provider_rules = [r for r in catalog["rules"] if affects_providers(r)]
    excluded = [r for r in catalog["rules"] if not affects_providers(r)]

    frr_tier, ksi_tier = get_class_a_lists()
    subset_excluded_a = []
    subset_excluded_b = []
    subset_excluded_c = []
    profile_a, missing_a = build_class_a_profile(
        catalog["rules"], frr_tier, subset_excluded_a)
    profile_b = build_class_profile(provider_rules, "b", subset_excluded_b)
    profile_c = build_class_profile(provider_rules, "c", subset_excluded_c)
    overlay = build_overlay(profile_b, profile_c)
    subset_excluded_d = []
    profile_d, delta_d = build_class_d_register(
        provider_rules, profile_c, subset_excluded_d)
    ksi_profile = build_ksi_profile(ksi_catalog["indicators"], ksi_tier)

    for sub in ("common", "class-a", "class-b", "class-c", "class-d-future"):
        os.makedirs(os.path.join(PROFILES, sub), exist_ok=True)

    def dump(obj, *parts):
        with open(os.path.join(PROFILES, *parts), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(obj, f, indent=1)

    dump(
        {
            "meta": {
                **meta,
                "class_a_note": (
                    "Class A applicability is enumerated by FRC-CLA-MFR "
                    "(mandatory), FRC-CLA-RFR (recommended), and FRC-CLA-OFR "
                    "(optional), parsed directly from the canonical dataset. "
                    "It is NOT blanket provider-rule applicability. On-ramp: "
                    "SOC 2 Type II, Rev5, or GovRAMP completed within the past "
                    "12 months (FRC-CLA-ASF). Agencies are limited to 12 months "
                    "of use unless the provider actively pursues Class B, C, "
                    "or D (AGU-USE-CLA)."
                ),
                "class_a_ksis": ksi_tier,
                "unresolved_rule_ids": missing_a,
                "unresolved_note": (
                    "Rules listed by FRC-CLA-RFR/OFR but absent from the "
                    "catalog. Known case: CPO-CSF-CPM is Rev5-only "
                    "(Certification Package Maintenance for Rev5); the RFR "
                    "list marks it 'if applicable' and it does not apply to "
                    "a 20x Program Certification profile."
                ),
            },
            "count": len(profile_a),
            "rules": profile_a,
        },
        "class-a", "profile.json")
    dump({"meta": meta, "count": len(profile_b), "rules": profile_b},
         "class-b", "profile.json")
    dump({"meta": meta, "count": len(profile_c), "rules": profile_c},
         "class-c", "profile.json")
    dump({"meta": meta, "overlay": overlay}, "class-c", "overlay.json")
    dump(
        {
            "meta": {
                **meta,
                "status": "FedRAMP pending",
                "class_d_note": (
                    "Future readiness register only. The 20x Program path "
                    "for Class D is listed by FedRAMP as coming in 2027 and "
                    "Class D specifics are set during the 20x Phase 4 Pilot. "
                    "This register never claims Class D compliance; it shows "
                    "the rules that would apply, resolved with the class d "
                    "variants already present in the canonical dataset, and "
                    "the delta against Class C so a Class C provider can see "
                    "what tightens. Known anchors: FRC-CSX-VVK requires at "
                    "least 4 automated verification and validation methods "
                    "per KSI at Class D; VDR-TFR-PSD sample detection within "
                    "1 day; SDR-CSX-KMT historical metrics must "
                    "significantly supersede lower classes, specifics "
                    "pending."
                ),
            },
            "count": len(profile_d),
            "delta_from_class_c": delta_d,
            "rules": profile_d,
        },
        "class-d-future", "readiness-register.json")
    dump({"meta": meta, "count": len(ksi_profile), "indicators": ksi_profile},
         "common", "ksi-profile.json")
    dump(
        {
            "meta": meta,
            "note": "Rules in the catalog that do not affect Providers; retained for traceability only.",
            "count": len(excluded),
            "rules": [
                {"rule_id": r["rule_id"], "family": r["family"], "affects": r["affects"]}
                for r in excluded
            ],
            "subset_applicability_excluded_note": (
                "Provider rules excluded because their subset applicability "
                "(types/paths/classes) does not match the target profile of "
                "20x Program Certification. Found via validation against the "
                "live fedramp.gov per-class ruleset reference on 2026-09-03."
            ),
            "subset_applicability_excluded_class_a": subset_excluded_a,
            "subset_applicability_excluded_class_b": subset_excluded_b,
            "subset_applicability_excluded_class_c": subset_excluded_c,
            "subset_applicability_excluded_class_d": subset_excluded_d,
        },
        "common", "non-provider-rules.json",
    )

    print("provider-affecting rules:", len(provider_rules))
    print("excluded non-provider rules:", len(excluded))
    print("class A resolved rules:", len(profile_a))
    print("class B resolved rules:", len(profile_b))
    print("class C resolved rules:", len(profile_c))
    print("class D readiness rules:", len(profile_d),
          "| delta from C:", len(delta_d))
    print("overlay added:", len(overlay["added"]),
          "changed:", len(overlay["changed"]),
          "removed:", len(overlay["removed"]))
    print("ksi entries:", len(ksi_profile))
    return 0


if __name__ == "__main__":
    sys.exit(main())
