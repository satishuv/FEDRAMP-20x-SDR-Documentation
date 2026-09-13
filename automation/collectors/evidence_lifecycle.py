#!/usr/bin/env python3
"""Evidence lifecycle: freshness, expiry, and tamper-evident integrity.

Extends the existing evidence model (evidence_wiring.py, which already hashes
each fact) with an explicit lifecycle so a reviewer can tell current evidence
from stale, expired, missing, superseded, or tampered evidence.

Hard boundary, preserved from the rest of the framework:
  - collection failure  != control failure
  - stale evidence      != noncompliance
  - missing evidence     != an automatic implementation-status change
Nothing here sets or changes a status. It classifies evidence state only; a
human still assesses.

Lifecycle states:
  current          fresh and within its freshness window
  stale            past the freshness window but not yet expired
  expired          past its expiry
  missing          no evidence present
  collection-error the collector could not read the source
  superseded       replaced by a newer evidence object
  integrity-failed the artifact's recomputed hash does not match the stored one

Offline: pure functions over evidence dicts and a reference 'now'. Run tests:
  python automation/collectors/test_evidence_lifecycle.py
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402

DEFAULT_FRESHNESS_DAYS = 1


def _parse(ts):
    if not ts:
        return None
    s = str(ts).replace("Z", "+00:00")
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.datetime.fromisoformat(s[:10])
        except ValueError:
            return None
    return d


def classify_freshness(observed_at, now, freshness_policy_days=DEFAULT_FRESHNESS_DAYS,
                       collection_status="success"):
    """Return (freshness_status, expires_at_iso) for one evidence observation.
    A collection error short-circuits to 'collection-error'; no observation is
    'missing'."""
    if collection_status and collection_status != "success":
        return "collection-error", None
    obs = _parse(observed_at)
    if obs is None:
        return "missing", None
    if obs.tzinfo is None:
        obs = obs.replace(tzinfo=datetime.timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=datetime.timezone.utc)
    expires = obs + datetime.timedelta(days=freshness_policy_days)
    # Grace: 'stale' between the freshness window and 2x it; 'expired' beyond.
    hard_expiry = obs + datetime.timedelta(days=freshness_policy_days * 2)
    if now <= expires:
        status = "current"
    elif now <= hard_expiry:
        status = "stale"
    else:
        status = "expired"
    return status, expires.isoformat()


def lifecycle_record(evidence, now=None, freshness_policy_days=DEFAULT_FRESHNESS_DAYS,
                     collector=None, collector_version=None):
    """Wrap an SDR evidence dict with lifecycle metadata. Does not mutate the
    input. Returns a new dict carrying the lifecycle fields alongside the
    original evidence."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    observed = evidence.get("lastUpdated") or evidence.get("observed_at")
    collection_status = evidence.get("collection_status", "success")
    freshness, expires = classify_freshness(
        observed, now, freshness_policy_days, collection_status)
    return {
        "evidence_id": evidence.get("evidence_id") or _derive_id(evidence),
        "source": (evidence.get("evidenceText", "").split(":")[0] or "unknown"),
        "collector": collector,
        "collector_version": collector_version,
        "observed_at": observed,
        "content_hash": evidence.get("xEvidenceContentHash"),
        "artifact_uri": evidence.get("evidenceLocation"),
        "freshness_policy_days": freshness_policy_days,
        "expires_at": expires,
        "freshness_status": freshness,
        "collection_status": collection_status,
        "review_status": evidence.get("review_status", "unreviewed"),
        "supersedes": evidence.get("supersedes"),
        "evidence": evidence,
    }


def _derive_id(evidence):
    h = evidence.get("xEvidenceContentHash", "")
    tail = h.split(":")[-1][:12] if h else "unknown"
    return f"EV-{tail}"


def verify_integrity(evidence, source_fact):
    """Recompute the hash of the source fact and compare to the stored hash on
    the evidence object. Returns (ok, detail). A mismatch is an integrity
    failure: the artifact changed after the digest was recorded. The stored hash
    is computed over the SANITIZED fact (the same projection persisted as
    xSourceFact), so recompute over the same sanitized projection here."""
    stored = evidence.get("xEvidenceContentHash")
    if not stored:
        return False, "no stored content hash"
    recomputed = ew.evidence_hash(ew._sanitize_fact_for_evidence(source_fact))
    if recomputed != stored:
        return False, f"integrity-failed: stored {stored[:20]} != recomputed {recomputed[:20]}"
    return True, "integrity ok"


def is_placeholder_uri(uri):
    """A template/placeholder evidence location, not a real artifact URI."""
    return bool(uri) and uri.startswith("sdr://placeholder/")


def collector_health(collector, *, last_success=None, last_error=None,
                     duration_ms=None, objects_collected=None,
                     regions_expected=None, regions_collected=None):
    """Build a collector-health record so a broken collection is
    distinguishable from a clean security posture. A collector that errored, or
    saw fewer regions than expected, is 'degraded'/'failed', never silently
    'no findings'."""
    if last_error:
        status = "failed"
    elif (regions_expected is not None and regions_collected is not None
          and regions_collected < regions_expected):
        status = "degraded"
    elif last_success:
        status = "complete"
    else:
        status = "not-run"
    return {
        "collector": collector,
        "status": status,
        "last_success": last_success,
        "last_error": last_error,
        "duration_ms": duration_ms,
        "objects_collected": objects_collected,
        "regions_expected": regions_expected,
        "regions_collected": regions_collected,
        "coverage_status": ("complete" if status == "complete" else status),
    }


def supersede(history, new_evidence, now=None):
    """Append new evidence to an immutable history list without dropping the
    prior entries: the newest entry records `supersedes` pointing at the prior
    content hash, so continuity is provable rather than overwritten. Returns a
    new history list (does not mutate the input)."""
    history = list(history or [])
    prior_hash = history[-1].get("content_hash") if history else None
    entry = dict(new_evidence)
    entry.setdefault("content_hash", new_evidence.get("xEvidenceContentHash"))
    entry["supersedes"] = prior_hash
    history.append(entry)
    return history
