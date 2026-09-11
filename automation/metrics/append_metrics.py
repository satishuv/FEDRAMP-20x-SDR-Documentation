# Metric-history appender (SDR-CSX-KMT accumulation).
#
# SDR-CSX-KMT requires, per applicable Key Security Indicator (verified against
# the pinned dataset 2026.07.14.01):
#   Class B: a 30-day summary and an up-to-one-year summary.
#   Class C: those two PLUS all daily metric data up to the past year.
# None of that can be produced retroactively, so it has to accumulate. This
# script appends exactly one dated datapoint per KSI per run to a history store
# and recomputes the summaries from it.
#
# Boundary, same as every other automation layer:
#   - It reads collected facts (telemetry) and writes a history store. It never
#     touches implementation_status, assessment, or a compliance conclusion.
#   - The datapoint is a count of passing vs total observed automated checks for
#     that KSI on that day: a metric, not a verdict.
#   - The history store is git-excluded (it derives from a real account).
#
# Deterministic given a fixed `today`, which is injectable so the offline tests
# do not depend on the wall clock.
#
# Usage: python automation/metrics/append_metrics.py [--profile NAME] is NOT
# how this runs; it consumes an already-collected facts store. Run the collector
# first, then this. In the scheduled loop the workflow chains them.

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
HISTORY = os.path.join(BASE, "automation", "metrics", "metric-history.json")

RETAIN_DAYS = 400  # a little over a year, so "up to the past year" is covered


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_facts():
    """Merge config-rule and posture facts from the store into per-KSI-relevant
    signals. Returns (config_by_rule, posture_by_service)."""
    config_by_rule = {}
    posture_by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return config_by_rule, posture_by_service
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not fn.startswith("facts-") or not fn.endswith(".json"):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        for fact in store.get("facts", []):
            config_by_rule[fact.get("rule")] = fact
        for pf in store.get("posture_facts", []):
            posture_by_service.setdefault(pf.get("service"), []).append(pf)
    return config_by_rule, posture_by_service


POSTURE_SERVICE_KEYS = {
    "security_hub": "AWS Security Hub",
    "access_analyzer": "Access Analyzer",
    "inspector": "Amazon Inspector",
    "guardduty": "Amazon GuardDuty",
    "backup": "AWS Backup",
    "kms": "AWS Key Management Service",
}
GOOD_CONFIG = {"COMPLIANT"}
GOOD_POSTURE = {"ENABLED", "PRESENT", "ACTIVE", "OBSERVED"}


def datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service):
    """One day's metric for a KSI: passing vs total observed automated checks.
    Returns None if nothing was observed (no datapoint rather than a zero, so a
    day the collector could not see a service is not recorded as a failure)."""
    passing = 0
    total = 0
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        fact = config_by_rule.get(check.get("target"))
        if not fact:
            continue
        ct = fact.get("compliance_type", "")
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        total += 1
        if ct in GOOD_CONFIG:
            passing += 1
    named = set(ksi_entry.get("services", []))
    for svc_key, svc_label in POSTURE_SERVICE_KEYS.items():
        if not any(svc_label in n for n in named):
            continue
        for pf in posture_by_service.get(svc_key, []):
            status = pf.get("status", "")
            if status.startswith("ERROR"):
                continue
            total += 1
            if status in GOOD_POSTURE:
                passing += 1
    if total == 0:
        return None
    return {"passing": passing, "total": total}


def summarize(points):
    """A summary is the average passing-fraction across the points and the
    count of days observed. Deterministic and simple on purpose: the assessor
    reads the daily series; this is the human-facing rollup."""
    if not points:
        return {"days_observed": 0, "avg_passing_fraction": None}
    fracs = [p["passing"] / p["total"] for p in points if p["total"]]
    avg = round(sum(fracs) / len(fracs), 4) if fracs else None
    return {"days_observed": len(points), "avg_passing_fraction": avg}


# FRC-CSX-MOT persistent-validation window, per class, verified verbatim
# against the pinned dataset: Class A MAY, Class B SHOULD, Class C MUST supply
# status from persistent validation over at least the past 6 months, Class D
# MUST over at least the past 18 months.
MOT_MIN_DAYS = {"a": 0, "b": 0, "c": 183, "d": 548}
MOT_FORCE = {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}


def mot_window(series, cls, today):
    """Assess the FRC-CSX-MOT persistent-validation window for one KSI.

    Reports the span the observed series actually covers and whether it meets
    the class minimum. This is a coverage measurement, not a determination: a
    covered window says validation status exists over that period, not that the
    control passed. An empty series reports covered=0 and meets=False for C/D.
    """
    cls = cls.lower()
    required = MOT_MIN_DAYS.get(cls, 0)
    force = MOT_FORCE.get(cls, "SHOULD")
    if series:
        earliest = min(datetime.fromisoformat(p["date"]).date() for p in series)
        covered = (today - earliest).days
    else:
        covered = 0
    meets = covered >= required if required else True
    return {
        "class": cls.upper(),
        "force": force,
        "required_days": required,
        "covered_days": covered,
        "meets_window": meets,
        "note": ("Coverage of the persistent-validation window, not a pass/fail "
                 "verdict. MUST at Class C (>=6 months) and Class D (>=18 months); "
                 "SHOULD at B; MAY at A."),
    }


def prune(series, today):
    cutoff = today - timedelta(days=RETAIN_DAYS)
    return [p for p in series if datetime.fromisoformat(p["date"]).date() >= cutoff]


def append_run(history, registry, config_by_rule, posture_by_service, today, cls="b"):
    """Append today's datapoint per KSI to the history and recompute summaries.
    One datapoint per KSI per calendar day; a second run the same day replaces
    that day's point rather than duplicating it (idempotent per day)."""
    date_str = today.isoformat()
    ksis = history.setdefault("ksis", {})
    appended = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        dp = datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service)
        if dp is None:
            continue
        entry = ksis.setdefault(kid, {"series": []})
        series = [p for p in entry["series"] if p["date"] != date_str]
        series.append({"date": date_str, **dp})
        series.sort(key=lambda p: p["date"])
        entry["series"] = prune(series, today)
        appended += 1
        # Recompute the SDR-CSX-KMT summaries.
        cutoff30 = (today - timedelta(days=30)).isoformat()
        last30 = [p for p in entry["series"] if p["date"] >= cutoff30]
        entry["last_30_days"] = summarize(last30)
        entry["up_to_one_year"] = summarize(entry["series"])
        # FRC-CSX-MOT persistent-validation window coverage for this class.
        entry["persistent_validation_window"] = mot_window(entry["series"], cls, today)
    history["meta"] = {
        "last_run": date_str,
        "retain_days": RETAIN_DAYS,
        "dataset_version": registry.get("meta", {}).get("dataset_version"),
        "note": ("Per-KSI daily metric history for SDR-CSX-KMT. A datapoint is "
                 "passing vs total observed automated checks that day, a metric, "
                 "not a compliance verdict. Git-excluded: derives from a real "
                 "account."),
    }
    return appended


def main():
    ap = argparse.ArgumentParser(
        description="Append one dated metric datapoint per KSI (SDR-CSX-KMT).")
    ap.add_argument("--today", default=None,
                    help="ISO date override for deterministic runs/tests")
    args = ap.parse_args()

    registry = load(REGISTRY)
    if registry is None:
        print("Could not load the collector registry.")
        return 2
    config_by_rule, posture_by_service = load_facts()
    if not config_by_rule and not posture_by_service:
        print("No facts found in automation/facts/. Run the collector first.")
        return 1

    today = (datetime.fromisoformat(args.today).date() if args.today
             else datetime.now(timezone.utc).date())
    history = load(HISTORY, {}) or {}
    # Class drives the FRC-CSX-MOT window requirement (6 months at C, 18 at D).
    offering = load(os.path.join(BASE, "profiles", "common", "offering-profile.json"), {})
    cls = (offering.get("certification_class") or "b").lower()
    appended = append_run(history, registry, config_by_rule, posture_by_service, today, cls)

    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    with open(HISTORY, "w", encoding="utf-8", newline="\n") as f:
        json.dump(history, f, indent=1)
    print(f"Appended {today.isoformat()} datapoint for {appended} KSI(s). "
          f"History: {os.path.relpath(HISTORY, BASE)} "
          f"({len(history.get('ksis', {}))} KSIs tracked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
