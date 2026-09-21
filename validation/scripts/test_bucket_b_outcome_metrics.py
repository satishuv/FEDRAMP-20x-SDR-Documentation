# Bucket-B outcome-metric contract test (PR-6).
#
# Finding: a bucket_b KSI (document/process evidence: training records,
# reviewed procedures, after-action reports) has NO API posture source, so its
# provider-deployed method could assert only that the artifact EXISTS. Existence
# is not an outcome. Each bucket_b described method now carries a structured
# outcome_metric declaring the measurable signal the deployed rule/Lambda emits
# (config-rule compliance, or a CloudWatch coverage/freshness fraction), with a
# metric_id that keys the per-method telemetry series - the same binding
# convention the VVK method-to-telemetry gate enforces. This test asserts the
# contract is present and well-formed for exactly the provider-deployed KSIs,
# and absent from posture/config-rule checks.
#
# Run: python validation/scripts/test_bucket_b_outcome_metrics.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _bucket_b_ksis():
    p = os.path.join(BASE, "automation", "collectors",
                     "pending-ksi-classification.json")
    d = json.load(open(p, encoding="utf-8"))
    return set(d.get("bucket_b", {}).get("ksis", {}).keys())


REQUIRED_FIELDS = {"metric_id", "signal", "unit", "pass_when",
                   "emitted_by", "description"}


def main():
    bucket_b = _bucket_b_ksis()
    check("bucket_b has the 11 document/process-evidence KSIs", len(bucket_b) == 11)

    reg = json.load(open(os.path.join(BASE, "automation", "collectors",
                                      "registry.json"), encoding="utf-8"))
    ksis = reg["ksis"]

    # 1) Every bucket_b KSI's described methods carry a well-formed outcome_metric.
    for kid in sorted(bucket_b):
        methods = [c for c in ksis[kid]["checks"]
                   if c.get("type") == "described_method"]
        check(f"{kid}: has provider-deployed described method(s)", bool(methods))
        for c in methods:
            om = c.get("outcome_metric")
            check(f"{kid}:{c['source']}: outcome_metric present",
                  isinstance(om, dict))
            if isinstance(om, dict):
                check(f"{kid}:{c['source']}: outcome_metric has all required fields",
                      REQUIRED_FIELDS <= set(om.keys()))
                # metric_id must key the per-method telemetry (VVK binding
                # convention): non-empty and namespaced to the KSI.
                check(f"{kid}:{c['source']}: outcome_metric.metric_id is KSI-scoped",
                      isinstance(om.get("metric_id"), str)
                      and om["metric_id"].startswith(kid))

    # 2) An outcome_metric appears ONLY on described methods, never on a
    #    config_managed_rule / posture check (those score their own signal).
    stray = [(kid, c.get("check_id"))
             for kid, v in ksis.items() for c in v["checks"]
             if c.get("type") != "described_method" and c.get("outcome_metric")]
    check("no config-rule/posture check carries an outcome_metric", not stray)

    # 3) An outcome_metric appears ONLY on bucket_b KSIs (bucket_a described
    #    methods are read-only collectors, not provider-deployed outcomes).
    with_om = {kid for kid, v in ksis.items()
               if any(c.get("outcome_metric") for c in v["checks"])}
    check("outcome_metric is scoped exactly to bucket_b", with_om == bucket_b)

    print(f"\n{'PASS' if not _fail else 'FAIL'}: bucket-b outcome metrics "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
