# Adversarial tests for the evidence-freshness classifier used by the SDR
# submission gate (sdr.py cmd_preflight).
#
# Finding closed here (external audit of c6d1322): evidence_lifecycle.py could
# classify current/stale/expired, but package-preflight never enforced it, so a
# populated Class C record backed only by expired evidence could still reach
# READY. FedRAMP guidance is explicit that expired exports / old evidence can
# cause rejection. The gate blocks on EXPIRED evidence for populated applicable
# records at Class C/D (advisory at A/B), warns on STALE, and never treats
# UNDATED/MISSING evidence as expiry (that is the linkage check's job) - it
# classifies only and never changes a status.
#
# Run: python validation/scripts/test_evidence_freshness.py

import datetime
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

_fail = 0
NOW = datetime.datetime(2026, 9, 18, 12, 0, 0, tzinfo=datetime.timezone.utc)
POLICY = 90  # default policy days; hard expiry at 2x = 180 days


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def main():
    cf = sdr.classify_evidence_freshness

    # Boundary: within policy -> current; just past policy -> stale; past 2x -> expired.
    check("today's observation is current",
          cf(NOW.isoformat(), NOW, POLICY) == "current")
    check("observation 30 days old is current (< 90)",
          cf((NOW - datetime.timedelta(days=30)).isoformat(), NOW, POLICY) == "current")
    check("observation 100 days old is stale (90 < d <= 180)",
          cf((NOW - datetime.timedelta(days=100)).isoformat(), NOW, POLICY) == "stale")
    check("observation 200 days old is expired (> 180)",
          cf((NOW - datetime.timedelta(days=200)).isoformat(), NOW, POLICY) == "expired")

    # Exact boundaries: policy_days == current edge; 2x == stale edge.
    check("exactly 90 days old is still current (inclusive fresh_until)",
          cf((NOW - datetime.timedelta(days=90)).isoformat(), NOW, POLICY) == "current")
    check("exactly 180 days old is still stale (inclusive hard_expiry)",
          cf((NOW - datetime.timedelta(days=180)).isoformat(), NOW, POLICY) == "stale")
    check("181 days old tips to expired",
          cf((NOW - datetime.timedelta(days=181)).isoformat(), NOW, POLICY) == "expired")

    # Date-only ISO (the collector writes lastUpdated as a date, not datetime).
    check("date-only observation parses and classifies",
          cf("2026-09-01", NOW, POLICY) == "current")

    # Undated / unparseable -> 'undated', NEVER expired (linkage check owns missing).
    check("None observation is undated, not expired",
          cf(None, NOW, POLICY) == "undated")
    check("empty string is undated", cf("", NOW, POLICY) == "undated")
    check("garbage timestamp is undated (not a false expiry)",
          cf("not-a-date", NOW, POLICY) == "undated")

    # Custom policy: a tighter 7-day policy makes a 10-day-old obs stale.
    check("a 10-day obs is stale under a 7-day policy (2x=14)",
          cf((NOW - datetime.timedelta(days=10)).isoformat(), NOW, 7) == "stale")
    check("a 20-day obs is expired under a 7-day policy",
          cf((NOW - datetime.timedelta(days=20)).isoformat(), NOW, 7) == "expired")

    # _evidence_observed_at tolerates the three field names.
    eoa = sdr._evidence_observed_at
    check("_evidence_observed_at reads lastUpdated",
          eoa({"lastUpdated": "2026-09-01"}) == "2026-09-01")
    check("_evidence_observed_at reads collected_at",
          eoa({"collected_at": "2026-09-02T00:00:00Z"}) == "2026-09-02T00:00:00Z")
    check("_evidence_observed_at reads observed_at",
          eoa({"observed_at": "2026-09-03"}) == "2026-09-03")
    check("_evidence_observed_at returns None for a locationless/dateless entry",
          eoa({"evidenceType": "Report"}) is None)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: evidence freshness "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
