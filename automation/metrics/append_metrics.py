# Metric-history appender (SDR-CSX-KMT accumulation).
#
# SDR-CSX-KMT requires, per applicable Key Security Indicator (verified against
# the pinned CR26 dataset):
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

# Route posture telemetry to KSI metrics using the SINGLE canonical collector
# service registry, the same source prefill and AI use, so metric history cannot
# ignore a service the collectors emit (a stale local whitelist previously
# routed only six of the seventeen collected services - CloudFormation, WAF,
# EC2, ECR, DynamoDB, EventBridge, Config, CloudTrail, S3, and IAM posture was
# silently dropped from the metric even when a KSI named them).
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from service_registry import SERVICE_DISPLAY_NAMES as POSTURE_SERVICE_KEYS
except Exception as exc:  # fail loud: unrouted telemetry is the failure to prevent
    raise RuntimeError(
        "append_metrics could not import the canonical service registry "
        "(automation/collectors/service_registry.py); refusing to run with an "
        "unknown posture-service routing set: " + str(exc)
    )

RETAIN_DAYS = 400  # a little over a year, so "up to the past year" is covered


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_facts():
    """Merge config-rule and posture facts from the store into per-KSI-relevant
    signals. Returns (config_by_rule, posture_by_service).

    config_by_rule maps a rule name to a LIST of that rule's facts, one per
    (region[, account]) scope observed. Finding F04: keying by rule name alone
    let a later region's file silently OVERWRITE an earlier region's result for
    the same rule (files load in sorted order), so a us-east-1 NON_COMPLIANT
    could vanish behind a us-west-2 COMPLIANT and the KSI read fully passing.
    Retaining every scope's fact lets datapoint_for_ksi aggregate across scopes
    (a failure in ANY scope counts) instead of last-writer-wins."""
    config_by_rule = {}
    posture_by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return config_by_rule, posture_by_service
    # De-duplicate identical (rule, region, account) observations so re-reading
    # the same file, or two files for the same scope, does not double-count.
    seen_scopes = {}
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not fn.startswith("facts-") or not fn.endswith(".json"):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        store_ts = (store.get("meta") or {}).get("collected_at")
        for fact in store.get("facts", []):
            # F05: ensure an observation timestamp is present so the appender can
            # tell a fresh measurement from a replayed stale one. Config facts
            # carry collected_at; fall back to the store's meta timestamp.
            if not fact.get("collected_at") and store_ts:
                fact = {**fact, "collected_at": store_ts}
            rule = fact.get("rule")
            scope = (rule, fact.get("region"), fact.get("account"))
            # Latest file wins for the SAME exact scope; different scopes are
            # all retained.
            seen_scopes[scope] = fact
        for pf in store.get("posture_facts", []):
            if not pf.get("collected_at") and store_ts:
                pf = {**pf, "collected_at": store_ts}
            posture_by_service.setdefault(pf.get("service"), []).append(pf)
    for (rule, _region, _account), fact in seen_scopes.items():
        config_by_rule.setdefault(rule, []).append(fact)
    return config_by_rule, posture_by_service


GOOD_CONFIG = {"COMPLIANT"}
# A posture status that is itself a binary good/bad signal (no ratio needed).
# NOTE: "OBSERVED" is deliberately NOT here. OBSERVED means "we successfully
# measured something", not "the measured thing passed". An OBSERVED fact scores
# ONLY through its structured measured/total ratio; an OBSERVED fact with no
# measured/total contributes NOTHING to the passing/total tally (it is an
# observation, not a pass). See finding: OBSERVED-counts-as-passing.
GOOD_POSTURE = {"ENABLED", "PRESENT", "ACTIVE"}
# A posture status that is an explicit EVALUATED NEGATIVE: the control was
# checked and found absent/off. These are definite failures and MUST enter the
# tally as (0, 1) - dropping them (as the old code did, returning None for every
# non-good status) created survivor bias where known failures vanished from the
# denominator while passing observations stayed in it, so an aggregate could
# read fully passing even though a routed collector reported a definite negative.
# NOTE: this is distinct from "no resource to evaluate" (NO_KEYS / NO_REPOS /
# NO_STACKS) and from "unmeasured" (ERROR* / UNKNOWN): those carry no evaluated
# outcome and stay skipped (None). See finding F-04.
BAD_POSTURE = {"NOT_ENABLED", "NOT_CONFIGURED", "NONE", "DISABLED", "INACTIVE",
               "ABSENT"}
# No-resource states: the check ran but there was nothing to evaluate (e.g. no
# KMS keys exist, so key-rotation is vacuously not a failure). No evaluated
# outcome -> skip, do NOT score as a failure.
NO_RESOURCE = {"NO_KEYS", "NO_REPOS", "NO_STACKS"}


def _posture_score(pf):
    """Score one posture fact as (passing, total) contribution, or None to skip.

    - ERROR / UNKNOWN statuses: skip (unmeasured, not an evaluated outcome).
    - No-resource statuses (NO_KEYS/NO_REPOS/NO_STACKS): skip (nothing to
      evaluate; not a failure).
    - A structured ratio (measured/total): use it directly - this is the real
      fraction in good posture (e.g. 0 of 50 keys rotating = 0/50, NOT a pass).
    - A binary good status in GOOD_POSTURE: 1 of 1.
    - An explicit evaluated negative in BAD_POSTURE: 0 of 1 - a definite failure
      that MUST count against the passing fraction (finding F-04).
    - A bare OBSERVED (or any other non-good, non-negative status) with no ratio:
      skip. An observation that something was measured is not evidence it passed
      or failed, so it must not inflate the passing count OR the total.
    """
    status = pf.get("status", "")
    if status.startswith("ERROR") or status == "UNKNOWN":
        return None
    if status in NO_RESOURCE:
        return None
    if "measured" in pf and "total" in pf:
        total = pf.get("total") or 0
        if total <= 0:
            return None
        return (pf.get("measured") or 0, total)
    if status in GOOD_POSTURE:
        return (1, 1)
    if status in BAD_POSTURE:
        # Explicit evaluated negative: definite fail, counts as 0 of 1.
        return (0, 1)
    # Bare OBSERVED / other count-only observation with no ratio: not an
    # evaluated pass or fail - carries no outcome, so it is neither passing
    # nor a denominator.
    return None


def _config_scope_score(facts):
    """Aggregate a Config rule's per-scope facts (one per region/account) into
    (passing, total) where each evaluated scope is one unit. Finding F04: a
    NON_COMPLIANT in ANY scope must count as a failure and must NOT be hidden by
    a COMPLIANT in another scope. ERROR/RULE_NOT_DEPLOYED/UNKNOWN scopes carry
    no evaluated outcome and are skipped (not scored as failures). `facts` is
    the list stored under config_by_rule[rule]; a bare dict is tolerated for
    backward compatibility."""
    if isinstance(facts, dict):
        facts = [facts]
    passing = 0
    total = 0
    for fact in facts or []:
        ct = fact.get("compliance_type", "")
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        total += 1
        if ct in GOOD_CONFIG:
            passing += 1
    return passing, total


def datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service):
    """One day's metric for a KSI: passing vs total observed automated checks.
    Returns None if nothing was observed (no datapoint rather than a zero, so a
    day the collector could not see a service is not recorded as a failure)."""
    passing = 0
    total = 0
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        facts = config_by_rule.get(check.get("target"))
        if not facts:
            continue
        # F04: aggregate across every region/account scope, not last-writer-wins.
        p, t = _config_scope_score(facts)
        total += t
        passing += p
    # Posture routing is by the EXPLICIT per-KSI allowlist (metric_service_keys),
    # NOT prose service-name matching. A posture service contributes to this KSI
    # only if its collector key is on the KSI's allowlist. A KSI with no allowlist
    # (e.g. a document/process KSI) accrues no posture metric - closing the
    # generic-service fan-out where unrelated posture manufactured KSI history.
    allowed = set(ksi_entry.get("metric_service_keys", []))
    for svc_key in allowed:
        for pf in posture_by_service.get(svc_key, []):
            score = _posture_score(pf)
            if score is None:
                continue
            p, t = score
            total += t
            passing += p
    if total == 0:
        return None
    return {"passing": passing, "total": total}


def per_metric_datapoints_for_ksi(ksi_entry, config_by_rule, posture_by_service):
    """One day's metric PER METRIC for a KSI, preserving each metric's identity
    (finding 3). FedRAMP SDR-CSX-KMT says "Summary of EACH metric", but the
    aggregate datapoint_for_ksi collapses every check/service into a single
    passing/total for the whole KSI, losing which metric contributed what.

    Returns {metric_id: {"passing": p, "total": t, "objective": str, "source": str}}
    for every metric that was actually observed that day, or {} if none. A
    metric is one config-managed rule (keyed by its check_id) or one observed
    posture service (keyed by "posture:<service>"). The KSI-level aggregate
    remains the sum of these, so existing consumers are unchanged; this is the
    per-metric breakdown emitted ALONGSIDE the aggregate, never replacing it.
    """
    out = {}
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        target = check.get("target")
        facts = config_by_rule.get(target)
        if not facts:
            continue
        # F04: aggregate across every observed region/account scope.
        p, t = _config_scope_score(facts)
        if t == 0:
            continue
        mid = check.get("check_id") or f"config:{target}"
        out[mid] = {
            "passing": p,
            "total": t,
            "objective": check.get("description") or check.get("objective") or "",
            "source": f"AWS Config rule {target}",
        }
    allowed = set(ksi_entry.get("metric_service_keys", []))
    for svc_key in allowed:
        svc_label = POSTURE_SERVICE_KEYS.get(svc_key, svc_key)
        obs = posture_by_service.get(svc_key, [])
        p = t = 0
        for pf in obs:
            score = _posture_score(pf)
            if score is None:
                continue
            sp, st = score
            t += st
            p += sp
        if t:
            out[f"posture:{svc_key}"] = {
                "passing": p, "total": t,
                "objective": f"Posture of {svc_label}",
                "source": f"Security posture telemetry for {svc_label}",
            }
    return out


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
MOT_MIN_MONTHS = {"a": 0, "b": 0, "c": 6, "d": 18}
MOT_MIN_DAYS = {"a": 0, "b": 0, "c": 183, "d": 548}  # informative approximation only
MOT_FORCE = {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}


def _months_before(ref, n):
    """The date exactly n CALENDAR months before ref, clamping to month-end.

    FedRAMP states the MOT window in calendar months ("at least the past 6/18
    months"), not fixed days; a day approximation is wrong at month boundaries.
    """
    y = ref.year + (ref.month - 1 - n) // 12
    m = (ref.month - 1 - n) % 12 + 1
    if m == 12:
        last = 31
    else:
        last = (datetime(y, m + 1, 1).date() - timedelta(days=1)).day
    return datetime(y, m, min(ref.day, last)).date()


def mot_window(series, cls, today):
    """Assess the FRC-CSX-MOT persistent-validation window for one KSI.

    Reports the span the observed series actually covers and whether it meets
    the class minimum. This is a coverage measurement, not a determination: a
    covered window says validation status exists over that period, not that the
    control passed. An empty series reports covered=0 and meets=False for C/D.
    The window is measured in CALENDAR MONTHS (the dataset's unit); covered_days
    is reported for information only.
    """
    cls = cls.lower()
    required_months = MOT_MIN_MONTHS.get(cls, 0)
    required = MOT_MIN_DAYS.get(cls, 0)
    force = MOT_FORCE.get(cls, "SHOULD")
    if series:
        earliest = min(datetime.fromisoformat(p["date"]).date() for p in series)
        covered = (today - earliest).days
        meets = True if not required_months else earliest <= _months_before(today, required_months)
    else:
        earliest = None
        covered = 0
        meets = not required_months
    return {
        "class": cls.upper(),
        "force": force,
        "required_months": required_months,
        "required_days": required,
        "covered_days": covered,
        "meets_window": meets,
        "note": ("Coverage of the persistent-validation window, not a pass/fail "
                 "verdict. Measured in calendar months. MUST at Class C "
                 "(>=6 months) and Class D (>=18 months); SHOULD at B; MAY at A."),
    }


def prune(series, today):
    cutoff = today - timedelta(days=RETAIN_DAYS)
    return [p for p in series if datetime.fromisoformat(p["date"]).date() >= cutoff]


def _obs_date(ts):
    """Parse a fact's collected_at into a date, or None if unparseable."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return datetime.fromisoformat(str(ts)[:10]).date()
        except ValueError:
            return None


def _ksi_observed_today(ksi_entry, config_by_rule, posture_by_service, today):
    """True if ANY fact contributing to this KSI was actually OBSERVED on
    `today` (finding F05). Prevents a stale/replayed fact (an old observation
    re-read on a later run) from being stamped as a fresh datapoint and
    manufacturing persistence/history it did not earn. A fact with no parseable
    observation timestamp is treated as NOT fresh (fail-closed for replay)."""
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        facts = config_by_rule.get(check.get("target"))
        if isinstance(facts, dict):
            facts = [facts]
        for fact in facts or []:
            if _obs_date(fact.get("collected_at")) == today:
                return True
    allowed = set(ksi_entry.get("metric_service_keys", []))
    for svc_key in allowed:
        for pf in posture_by_service.get(svc_key, []):
            if _obs_date(pf.get("collected_at")) == today:
                return True
    return False


def append_run(history, registry, config_by_rule, posture_by_service, today,
               cls="b", require_fresh=False):
    """Append today's datapoint per KSI to the history and recompute summaries.
    One datapoint per KSI per calendar day; a second run the same day replaces
    that day's point rather than duplicating it (idempotent per day).

    F05: when require_fresh is set (production main() sets it), a KSI datapoint
    is recorded for `today` only if at least one contributing observation was
    actually collected on `today`. This stops a replayed stale fact from
    advancing the history/MOT clock with a measurement that never happened that
    day. The library default is False so callers computing summaries over
    explicitly-dated synthetic series are unaffected; the collection pipeline
    (main) always enforces freshness."""
    date_str = today.isoformat()
    ksis = history.setdefault("ksis", {})
    appended = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        dp = datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service)
        if dp is None:
            continue
        if require_fresh and not _ksi_observed_today(
                ksi_entry, config_by_rule, posture_by_service, today):
            # Stale/replayed observation only: do not manufacture a fresh point.
            continue
        entry = ksis.setdefault(kid, {"series": []})
        series = [p for p in entry["series"] if p["date"] != date_str]
        series.append({"date": date_str, **dp})
        series.sort(key=lambda p: p["date"])
        entry["series"] = prune(series, today)
        appended += 1
        # Recompute the SDR-CSX-KMT summaries. Storage keeps RETAIN_DAYS (~400)
        # of history, but each summary MUST slice the retained series to the
        # EXACT window FedRAMP names, not the whole retained span:
        #   - "past 30 days"  = the 30 calendar dates today-29 .. today
        #     (an inclusive `date >= today-30` window spans 31 dates, so it is
        #      wrong by one; use today-29 for exactly 30).
        #   - "up to the past year" = the >= 12-calendar-months window
        #     (today back to _months_before(today, 12)); summarizing the whole
        #      ~400-day retained series over-counts beyond a year.
        cutoff30 = (today - timedelta(days=29)).isoformat()
        last30 = [p for p in entry["series"] if p["date"] >= cutoff30]
        entry["last_30_days"] = summarize(last30)
        year_start = _months_before(today, 12).isoformat()
        last_year = [p for p in entry["series"] if p["date"] >= year_start]
        entry["up_to_one_year"] = summarize(last_year)
        # FRC-CSX-MOT persistent-validation window coverage for this class.
        entry["persistent_validation_window"] = mot_window(entry["series"], cls, today)
        # Per-metric identity (finding 3): FedRAMP asks for a summary of EACH
        # metric, so accumulate a per-metric daily series ALONGSIDE the KSI
        # aggregate above (never replacing it). Each metric keeps its own
        # series, 30-day and 1-year summaries, objective, and source, sliced to
        # the same exact windows. The KSI aggregate remains the sum, so every
        # existing consumer is unchanged.
        pm = per_metric_datapoints_for_ksi(ksi_entry, config_by_rule, posture_by_service)
        metrics = entry.setdefault("metrics", {})
        for mid, mdp in pm.items():
            m = metrics.setdefault(mid, {"series": []})
            m_series = [p for p in m["series"] if p["date"] != date_str]
            m_series.append({"date": date_str,
                             "passing": mdp["passing"], "total": mdp["total"]})
            m_series.sort(key=lambda p: p["date"])
            m["series"] = prune(m_series, today)
            m["objective"] = mdp.get("objective", "")
            m["source"] = mdp.get("source", "")
            m["last_30_days"] = summarize(
                [p for p in m["series"] if p["date"] >= cutoff30])
            m["up_to_one_year"] = summarize(
                [p for p in m["series"] if p["date"] >= year_start])
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


def load_history_safe(path):
    """Load existing metric history, distinguishing three cases (finding F07):
      - file ABSENT  -> ({}, None): a legitimate first run, start fresh.
      - file PRESENT and valid history object -> (history, None).
      - file PRESENT but unreadable / invalid JSON / wrong shape -> ({}, error):
        the caller MUST abort rather than overwrite. The old code ran the file
        through load(), which turned a JSON decode error into {} and then
        rewrote a fresh one-day history over the corrupt (but real) durable
        state - silent data loss. Corruption is not a first run.
    """
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        return {}, f"metric history unreadable: {e}"
    except ValueError as e:
        return {}, f"metric history is not valid JSON: {e}"
    if not isinstance(data, dict):
        return {}, f"metric history root is {type(data).__name__}, expected object"
    ksis = data.get("ksis")
    if ksis is not None and not isinstance(ksis, dict):
        return {}, "metric history 'ksis' is present but not an object"
    return data, None


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
    # F07: fail closed on a corrupt existing history rather than overwriting it.
    history, hist_err = load_history_safe(HISTORY)
    if hist_err:
        print(f"FAIL: refusing to overwrite metric history - {hist_err}. "
              "The existing durable history is present but not safely readable; "
              "fix or restore it before appending (aborting to prevent data loss, "
              "finding F07).")
        return 1
    # Class drives the FRC-CSX-MOT window requirement (6 months at C, 18 at D).
    offering = load(os.path.join(BASE, "profiles", "common", "offering-profile.json"), {})
    cls = (offering.get("certification_class") or "b").lower()
    appended = append_run(history, registry, config_by_rule, posture_by_service,
                          today, cls, require_fresh=True)

    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    with open(HISTORY, "w", encoding="utf-8", newline="\n") as f:
        json.dump(history, f, indent=1)
    print(f"Appended {today.isoformat()} datapoint for {appended} KSI(s). "
          f"History: {os.path.relpath(HISTORY, BASE)} "
          f"({len(history.get('ksis', {}))} KSIs tracked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
