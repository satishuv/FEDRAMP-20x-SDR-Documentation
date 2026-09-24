# Offline tests for the metric-history appender. Exercises append_run directly
# with synthetic registry/facts, no files or account. Run:
#   python automation/metrics/test_append_metrics.py

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import append_metrics as am  # noqa: E402

REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {
    "KSI-A": {"services": ["AWS Config"], "metric_service_keys": [],
              "checks": [{"type": "config_managed_rule", "target": "r1"}]},
    "KSI-B": {"services": ["Amazon GuardDuty"], "metric_service_keys": ["guardduty"],
              "checks": []},
}}


def config(ct):
    return {"r1": {"rule": "r1", "compliance_type": ct}}


def guardduty(status):
    return {"guardduty": [{"service": "guardduty", "check": "detector", "status": status}]}


def test_datapoint_counts_passing_and_total():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("COMPLIANT"), {})
    assert dp == {"passing": 1, "total": 1}
    dp2 = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("NON_COMPLIANT"), {})
    assert dp2 == {"passing": 0, "total": 1}


def test_no_observation_yields_no_datapoint():
    # RULE_NOT_DEPLOYED is not an observation, so no datapoint (not a zero).
    assert am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("RULE_NOT_DEPLOYED"), {}) is None


def test_f04_region_failure_not_hidden_by_another_region():
    # Finding F04: a NON_COMPLIANT in us-east-1 must NOT be overwritten by a
    # COMPLIANT in us-west-2. Both scopes count: 1 passing of 2 total.
    facts = {"r1": [
        {"rule": "r1", "compliance_type": "NON_COMPLIANT", "region": "us-east-1"},
        {"rule": "r1", "compliance_type": "COMPLIANT", "region": "us-west-2"},
    ]}
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], facts, {})
    assert dp == {"passing": 1, "total": 2}, dp


def test_f04_load_facts_retains_every_region_scope(tmp_path=None):
    # load_facts must keep one fact per (rule, region, account), not last-wins.
    import json
    import tempfile
    d = tempfile.mkdtemp()
    for i, (region, ct) in enumerate([("us-east-1", "NON_COMPLIANT"),
                                      ("us-west-2", "COMPLIANT")]):
        with open(os.path.join(d, f"facts-{i}.json"), "w") as f:
            json.dump({"facts": [{"rule": "r1", "compliance_type": ct,
                                  "region": region}]}, f)
    orig = am.FACTS_DIR
    am.FACTS_DIR = d
    try:
        cbr, _ = am.load_facts()
    finally:
        am.FACTS_DIR = orig
    assert isinstance(cbr["r1"], list) and len(cbr["r1"]) == 2, cbr


def test_append_is_idempotent_per_day():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1, "same-day re-run must replace, not duplicate"


def test_append_accumulates_across_days():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    am.append_run(hist, REGISTRY, config("NON_COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 2
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2
    # avg of 1.0 and 0.0 = 0.5
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["avg_passing_fraction"] == 0.5


def test_posture_datapoint_for_guardduty_ksi():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-B"], {}, guardduty("ENABLED"))
    assert dp == {"passing": 1, "total": 1}


# --- OBSERVED-is-not-passing regression tests -------------------------------
# Finding: append_metrics previously put "OBSERVED" in GOOD_POSTURE, so a fact
# emitted as OBSERVED counted as a passing metric regardless of the underlying
# count. OBSERVED must score ONLY through a structured measured/total ratio; a
# bare OBSERVED with no ratio must contribute nothing to passing OR total.

def _posture(service, status, measured=None, total=None):
    pf = {"service": service, "check": "c", "status": status}
    if measured is not None:
        pf["measured"] = measured
    if total is not None:
        pf["total"] = total
    return {service: [pf]}


def test_observed_zero_ratio_scores_zero_not_pass():
    # 0 of 50 keys rotating, collected as OBSERVED, must be 0/50, never a pass.
    kms_ksi = {"metric_service_keys": ["kms"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED", 0, 50))
    assert dp == {"passing": 0, "total": 50}, dp


def test_observed_full_ratio_scores_full():
    kms_ksi = {"metric_service_keys": ["kms"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED", 50, 50))
    assert dp == {"passing": 50, "total": 50}, dp


def test_bare_observed_without_ratio_is_not_a_datapoint():
    # A count-only OBSERVED (e.g. "25 failed findings") carries no evaluated
    # outcome: it must not become 1/1 passing and must not inflate the total.
    kms_ksi = {"metric_service_keys": ["kms"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED"))
    assert dp is None, dp


def test_posture_score_helper():
    assert am._posture_score({"status": "OBSERVED", "measured": 0, "total": 50}) == (0, 50)
    assert am._posture_score({"status": "OBSERVED"}) is None
    assert am._posture_score({"status": "ENABLED"}) == (1, 1)
    assert am._posture_score({"status": "ERROR:X"}) is None
    assert am._posture_score({"status": "OBSERVED", "measured": 3, "total": 0}) is None


# --- F-04: explicit evaluated negatives are recorded, not dropped ------------
# Finding: every non-good status returned None, so explicit evaluated negatives
# (NONE, NOT_ENABLED, NOT_CONFIGURED) - definite failures the collectors emit -
# vanished from the tally, inflating the passing fraction (survivor bias). They
# must score (0, 1). Errors/unknown and no-resource states still skip.

def test_evaluated_negatives_score_zero_of_one():
    for bad in ("NOT_ENABLED", "NOT_CONFIGURED", "NONE", "DISABLED",
                "INACTIVE", "ABSENT"):
        assert am._posture_score({"status": bad}) == (0, 1), bad


def test_error_and_unknown_still_skip():
    assert am._posture_score({"status": "ERROR:AccessDenied"}) is None
    assert am._posture_score({"status": "UNKNOWN"}) is None


def test_no_resource_states_skip_not_fail():
    # Nothing to evaluate (no keys/repos/stacks) is NOT a failure.
    for nr in ("NO_KEYS", "NO_REPOS", "NO_STACKS"):
        assert am._posture_score({"status": nr}) is None, nr


def test_negative_posture_enters_datapoint_as_failing():
    # A routed collector reporting NOT_ENABLED must count as 0/1, not disappear.
    ksi = {"metric_service_keys": ["securityhub"], "checks": []}
    dp = am.datapoint_for_ksi(ksi, {}, _posture("securityhub", "NOT_ENABLED"))
    assert dp == {"passing": 0, "total": 1}, dp


def test_negative_does_not_get_masked_by_a_positive_sibling():
    # F-04 core: one source ENABLED (1/1) and another NOT_ENABLED (0/1) on the
    # same KSI must aggregate to 1/2, NOT 1/1 (the old drop-the-negative bug
    # made a known failure invisible so the KSI read fully passing).
    ksi = {"metric_service_keys": ["guardduty", "securityhub"], "checks": []}
    posture = {
        "guardduty": [{"service": "guardduty", "check": "detector", "status": "ENABLED"}],
        "securityhub": [{"service": "securityhub", "check": "enabled", "status": "NOT_ENABLED"}],
    }
    dp = am.datapoint_for_ksi(ksi, {}, posture)
    assert dp == {"passing": 1, "total": 2}, dp


# --- Explicit metric-source allowlist (no service-name fan-out) --------------
# Finding: routing posture to every KSI whose prose named a service let generic
# posture manufacture metric history for unrelated KSIs. Posture now routes ONLY
# via the KSI's explicit metric_service_keys allowlist.

def test_no_allowlist_means_no_posture_metric():
    # A KSI with an empty allowlist (e.g. a document/process KSI like CED-RAT)
    # accrues NO posture metric even when posture for that service was collected.
    doc_ksi = {"metric_service_keys": [], "checks": []}
    # s3/config/kms posture present, all with good ratios:
    posture = {
        "s3": [{"service": "s3", "status": "OBSERVED", "measured": 10, "total": 10}],
        "config": [{"service": "config", "status": "ENABLED"}],
        "kms": [{"service": "kms", "status": "OBSERVED", "measured": 5, "total": 5}],
    }
    assert am.datapoint_for_ksi(doc_ksi, {}, posture) is None


def test_posture_routes_only_to_allowlisted_service():
    # A KSI allowlisted for cloudformation must NOT pick up unrelated s3 posture.
    eis_ksi = {"metric_service_keys": ["cloudformation"], "checks": []}
    posture = {
        "cloudformation": [{"service": "cloudformation", "status": "OBSERVED",
                            "measured": 8, "total": 10}],
        "s3": [{"service": "s3", "status": "OBSERVED", "measured": 0, "total": 100}],
    }
    dp = am.datapoint_for_ksi(eis_ksi, {}, posture)
    # only the cloudformation 8/10 counts; the 0/100 s3 leak is excluded
    assert dp == {"passing": 8, "total": 10}, dp



def test_history_persists_across_ephemeral_runs():
    # Simulate the collector buildspec: each daily run is EPHEMERAL, so it must
    # restore the prior history (from S3), append one datapoint, and persist it.
    # If persistence works, day 2 sees day 1's datapoint; a run that started
    # empty each time (the bug) would only ever hold one point.
    import json
    import tempfile
    store = os.path.join(tempfile.mkdtemp(prefix="mh-"), "metric-history.json")

    # Run 1: no prior history on disk (fresh ephemeral container) -> "restore"
    # finds nothing -> start empty, append, persist.
    hist = am.load(store, {}) or {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist, f, indent=1)

    # Run 2: a NEW ephemeral container restores the persisted history, appends
    # the next day, and persists again.
    hist2 = am.load(store, {}) or {}
    assert hist2.get("ksis"), "run 2 must restore run 1's persisted history"
    am.append_run(hist2, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist2, f, indent=1)

    final = am.load(store, {})
    assert len(final["ksis"]["KSI-A"]["series"]) == 2, \
        "history must accumulate across ephemeral runs, not reset each run"


def test_pruning_drops_old_points():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2024, 1, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    dates = [p["date"] for p in hist["ksis"]["KSI-A"]["series"]]
    assert "2024-01-01" not in dates, "points older than RETAIN_DAYS must be pruned"
    assert "2026-09-06" in dates


def test_30_day_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 7, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    # Only the recent point is inside the 30-day window ending 2026-09-06.
    assert hist["ksis"]["KSI-A"]["last_30_days"]["days_observed"] == 1
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2


def test_mot_window_class_c_short_and_met():
    today = date(2026, 9, 6)
    # A single point today: 0 days covered, Class C requires 183 -> not met.
    short = am.mot_window([{"date": "2026-09-06", "passing": 1, "total": 1}], "c", today)
    assert short["force"] == "MUST"
    assert short["required_days"] == 183
    assert short["covered_days"] == 0
    assert short["meets_window"] is False
    # A point 200 days ago: covered >= 183 -> met.
    met = am.mot_window([{"date": "2026-02-18", "passing": 1, "total": 1}], "c", today)
    assert met["covered_days"] >= 183
    assert met["meets_window"] is True


def test_mot_window_class_d_needs_18_months():
    today = date(2026, 9, 6)
    w = am.mot_window([{"date": "2025-09-06", "passing": 1, "total": 1}], "d", today)
    # ~365 days covered is short of the 548-day (18 month) Class D requirement.
    assert w["required_days"] == 548
    assert w["meets_window"] is False


def test_mot_window_class_b_is_should_not_gated():
    today = date(2026, 9, 6)
    w = am.mot_window([], "b", today)
    assert w["force"] == "SHOULD"
    assert w["required_days"] == 0
    assert w["meets_window"] is True  # no minimum at B


def test_mot_window_calendar_month_boundary():
    # Regression for the day-approximation bug: a series whose earliest point is
    # exactly 6 CALENDAR months before today must MEET the Class C window, even
    # when that span is fewer than 183 days. 2026-03-16 -> 2026-09-16 is exactly
    # 6 calendar months but only 184 days; pick a span that a days>=183 rule
    # would still pass, and a case a day rule would WRONGLY fail.
    today = date(2026, 9, 16)
    # Exactly 6 calendar months back = 2026-03-16 (184 days) -> meets.
    at_boundary = am.mot_window([{"date": "2026-03-16", "passing": 1, "total": 1}], "c", today)
    assert at_boundary["meets_window"] is True
    # The Feb-boundary case that exposes the bug: today 2026-05-31, 6 months
    # back clamps to 2025-11-30. A point on 2025-11-30 is exactly 6 calendar
    # months (182 days, SHORT of 183) but must still MEET the window.
    today2 = date(2026, 5, 31)
    short_days = am.mot_window([{"date": "2025-11-30", "passing": 1, "total": 1}], "c", today2)
    assert short_days["covered_days"] < 183  # a day rule would call this short
    assert short_days["meets_window"] is True  # calendar months: exactly 6 -> met
    # And a point one day inside the window (later) must FAIL.
    inside = am.mot_window([{"date": "2025-12-01", "passing": 1, "total": 1}], "c", today2)
    assert inside["meets_window"] is False


def test_append_run_records_mot_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6), cls="c")
    w = hist["ksis"]["KSI-A"]["persistent_validation_window"]
    assert w["class"] == "C" and w["force"] == "MUST"


def test_f05_replayed_stale_fact_is_not_recorded_as_fresh():
    # Finding F05: a fact observed in the past, re-read on a later run, must NOT
    # be stamped as a fresh datapoint under require_fresh (production path).
    stale = {"r1": [{"rule": "r1", "compliance_type": "COMPLIANT",
                     "collected_at": "2025-01-01T00:00:00Z"}]}
    hist = {}
    for d in (date(2026, 9, 23), date(2026, 9, 24)):
        am.append_run(hist, REGISTRY, stale, {}, d, require_fresh=True)
    series = hist.get("ksis", {}).get("KSI-A", {}).get("series", [])
    assert series == [], f"replayed 2025 fact must not create 2026 points, got {series}"


def test_f05_fact_observed_today_is_recorded():
    # No over-block: a fact actually collected on the run day IS recorded.
    fresh = {"r1": [{"rule": "r1", "compliance_type": "COMPLIANT",
                     "collected_at": "2026-09-24T00:00:00Z"}]}
    hist = {}
    am.append_run(hist, REGISTRY, fresh, {}, date(2026, 9, 24), require_fresh=True)
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1 and series[0]["date"] == "2026-09-24"


def test_f07_corrupt_history_is_not_treated_as_first_run():
    # Finding F07: an existing but invalid-JSON history must NOT be silently
    # read as {} (a first run) and then overwritten. load_history_safe returns
    # an error the caller must honor.
    import tempfile
    fd = tempfile.mkdtemp()
    p = os.path.join(fd, "metric-history.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{ this is not valid json ")
    data, err = am.load_history_safe(p)
    assert err is not None and data == {}, (data, err)


def test_f07_absent_history_is_a_clean_first_run():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "metric-history.json")
    data, err = am.load_history_safe(p)
    assert err is None and data == {}, (data, err)


def test_f07_wrong_shape_history_is_rejected():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "metric-history.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("[1, 2, 3]")  # valid JSON, wrong root type
    data, err = am.load_history_safe(p)
    assert err is not None and data == {}, (data, err)


# --- F03: check-scoped posture routing -------------------------------------
_JIT = {"metric_service_keys": ["iam:role_session_duration"], "checks": []}


def test_f03_unrelated_check_does_not_score_check_scoped_ksi():
    # An IAM password_policy fact must NOT score a KSI scoped to a different IAM
    # check (the audit's KSI-IAM-JIT reproduction).
    dp = am.datapoint_for_ksi(_JIT, {}, {"iam": [
        {"service": "iam", "check": "password_policy", "status": "PRESENT"}]})
    assert dp is None, dp


def test_f03_matching_check_scores():
    dp = am.datapoint_for_ksi(_JIT, {}, {"iam": [
        {"service": "iam", "check": "role_session_duration",
         "status": "OBSERVED", "measured": 2, "total": 5}]})
    assert dp == {"passing": 2, "total": 5}, dp


def test_f03_per_metric_keeps_per_check_identity():
    ksi = {"metric_service_keys": ["s3"], "checks": []}
    pm = am.per_metric_datapoints_for_ksi(ksi, {}, {"s3": [
        {"service": "s3", "check": "encryption", "status": "OBSERVED",
         "measured": 1, "total": 1},
        {"service": "s3", "check": "public_access", "status": "OBSERVED",
         "measured": 0, "total": 1}]})
    assert "posture:s3:encryption" in pm and "posture:s3:public_access" in pm, pm
    assert pm["posture:s3:encryption"]["passing"] == 1
    assert pm["posture:s3:public_access"]["passing"] == 0


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
