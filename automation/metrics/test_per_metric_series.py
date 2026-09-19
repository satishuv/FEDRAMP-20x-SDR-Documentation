#!/usr/bin/env python3
"""Offline tests for per-metric KSI series (finding 3, SDR-CSX-KMT).

FedRAMP asks for a summary of EACH metric. The KSI-level datapoint collapses
every check/service into one passing/total, losing per-metric identity. These
tests prove append_metrics now accumulates a per-metric series ALONGSIDE the
KSI aggregate (never replacing it), and build_sdr derives a perMetric block for
the submitted document.

No AWS, no boto3, no disk (append side) plus a pure derivation check (build
side). Run:
    python automation/metrics/test_per_metric_series.py
"""

import os
import sys
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "validation", "scripts"))
import append_metrics as am  # noqa: E402
import build_sdr as bs  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS: {name}")
    else:
        FAIL += 1
        print(f"FAIL: {name}")


# A KSI with two distinct config-rule metrics.
REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {
    "KSI-X": {"services": ["AWS Config"], "checks": [
        {"check_id": "KSI-X:verify:config:rule-a", "type": "config_managed_rule",
         "service": "AWS Config", "target": "rule-a", "description": "Rule A objective"},
        {"check_id": "KSI-X:verify:config:rule-b", "type": "config_managed_rule",
         "service": "AWS Config", "target": "rule-b", "description": "Rule B objective"},
    ]},
}}


def _config(a_ct, b_ct):
    return {"rule-a": {"rule": "rule-a", "compliance_type": a_ct},
            "rule-b": {"rule": "rule-b", "compliance_type": b_ct}}


def test_aggregate_unchanged_by_per_metric():
    # rule-a passes, rule-b fails -> aggregate is 1/2 passing.
    hist = {}
    d = date(2026, 5, 1)
    am.append_run(hist, REGISTRY, _config("COMPLIANT", "NON_COMPLIANT"), {}, d)
    agg = hist["ksis"]["KSI-X"]["series"][-1]
    check("KSI aggregate remains passing=1 total=2 (unchanged behavior)",
          agg["passing"] == 1 and agg["total"] == 2)


def test_per_metric_series_recorded_separately():
    hist = {}
    d = date(2026, 5, 1)
    am.append_run(hist, REGISTRY, _config("COMPLIANT", "NON_COMPLIANT"), {}, d)
    metrics = hist["ksis"]["KSI-X"].get("metrics", {})
    check("both metric ids are recorded separately",
          set(metrics) == {"KSI-X:verify:config:rule-a", "KSI-X:verify:config:rule-b"})
    a = metrics["KSI-X:verify:config:rule-a"]["series"][-1]
    b = metrics["KSI-X:verify:config:rule-b"]["series"][-1]
    check("metric rule-a is passing 1/1", a["passing"] == 1 and a["total"] == 1)
    check("metric rule-b is failing 0/1", b["passing"] == 0 and b["total"] == 1)
    check("per-metric carries objective and source",
          metrics["KSI-X:verify:config:rule-a"]["objective"] == "Rule A objective"
          and "rule-a" in metrics["KSI-X:verify:config:rule-a"]["source"])


def test_per_metric_summaries_are_distinct():
    # rule-a always passes, rule-b always fails, over 40 days.
    hist = {}
    start = date(2026, 3, 1)
    for i in range(40):
        am.append_run(hist, REGISTRY, _config("COMPLIANT", "NON_COMPLIANT"),
                      {}, start + timedelta(days=i))
    m = hist["ksis"]["KSI-X"]["metrics"]
    check("rule-a 30-day avg is 1.0",
          m["KSI-X:verify:config:rule-a"]["last_30_days"]["avg_passing_fraction"] == 1.0)
    check("rule-b 30-day avg is 0.0",
          m["KSI-X:verify:config:rule-b"]["last_30_days"]["avg_passing_fraction"] == 0.0)


def test_build_derives_per_metric_block():
    # A metric-history with a per-metric map -> ksi_semantic emits perMetric.
    today = date.today().isoformat()
    mh = {"ksis": {"KSI-X": {
        "series": [{"date": today, "passing": 1, "total": 2}],
        "metrics": {
            "KSI-X:verify:config:rule-a": {
                "series": [{"date": today, "passing": 1, "total": 1}],
                "objective": "Rule A objective", "source": "AWS Config rule rule-a",
                "last_30_days": {"days_observed": 1, "avg_passing_fraction": 1.0},
                "up_to_one_year": {"days_observed": 1, "avg_passing_fraction": 1.0}},
        }}}}
    pm = bs._derive_per_metric("KSI-X", mh)
    block = bs.ksi_semantic({"extension": {}, "historical_metrics": {}},
                            daily_series=bs._derive_daily_data("KSI-X", mh),
                            per_metric=pm)["historicalMetrics"]
    check("perMetric block is emitted with the metric id",
          isinstance(block["perMetric"], list) and len(block["perMetric"]) == 1
          and block["perMetric"][0]["metricId"] == "KSI-X:verify:config:rule-a")
    check("perMetric carries objective, source, summaries and daily data",
          block["perMetric"][0]["objective"] == "Rule A objective"
          and block["perMetric"][0]["dailyData"])


def test_no_per_metric_history_yields_empty_block():
    # Older history without a "metrics" map -> perMetric is empty, no crash.
    today = date.today().isoformat()
    mh = {"ksis": {"KSI-X": {"series": [{"date": today, "passing": 1, "total": 1}]}}}
    pm = bs._derive_per_metric("KSI-X", mh)
    check("no per-metric history yields empty perMetric", pm == [])


def main():
    tests = [(k, v) for k, v in globals().items()
             if k.startswith("test_") and callable(v)]
    for _, fn in sorted(tests, key=lambda kv: kv[0]):
        fn()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
