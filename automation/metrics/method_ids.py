#!/usr/bin/env python3
"""Canonical metric / verification-method identity (AUD-F18).

FRC-CSX-VVK binding works only if three places agree on one string: the metric
engine keys each per-method series in metric-history.json by it, the prefill
writes it as `method_id` on each structured automated test, and the preflight
binding gate compares the two. Before this module each side derived its own
string and the real collector -> prefill -> preflight path never bound: prefill
wrote plain-text test lines (zero automated methods to the validator), so the
Class C sample "worked" only because it hand-wired both sides.

Two identities exist:

  config method  the registry check's `check_id`
                 (e.g. "KSI-IAM-ELP:verify:config:iam-policy-no-statements-with-admin-access"),
                 falling back to "config:<rule>" for a check with no id.
  posture method "posture:<service>:<check>" for one collector check
                 (e.g. "posture:kms:key_rotation").

A KSI's `metric_service_keys` allowlist routes posture facts to it. Every entry
MUST be check-scoped ("service:check"); a bare service key ("kms") is refused
(AUD-F16), because it scores every fact of that service, so an unrelated
good-looking check (Access Analyzer PRESENT) could lift a KSI that a related
check (active findings) says is failing.
"""

POSTURE_PREFIX = "posture:"


def config_method_id(check):
    """Identity of one config-managed-rule check (a registry `checks` entry)."""
    return check.get("check_id") or f"config:{check.get('target')}"


def posture_method_id(service, check):
    """Identity of one collector posture check."""
    return f"{POSTURE_PREFIX}{service}:{check or 'posture'}"


def parse_service_key(key):
    """Split a metric_service_keys entry into (service, check). check is None
    for a bare service key, which callers must refuse (see is_check_scoped)."""
    service, _, check = str(key).partition(":")
    return service, (check or None)


def is_check_scoped(key):
    service, check = parse_service_key(key)
    return bool(service) and bool(check)


def bare_service_keys(registry):
    """[(ksi_id, key)] for every allowlist entry that routes a whole service."""
    out = []
    for kid, entry in (registry.get("ksis") or {}).items():
        for key in entry.get("metric_service_keys") or []:
            if not is_check_scoped(key):
                out.append((kid, key))
    return out


def assert_check_scoped(registry):
    """Refuse a registry that routes any whole service to a KSI (AUD-F16)."""
    bare = bare_service_keys(registry)
    if bare:
        raise ValueError(
            "metric_service_keys must be check-scoped (service:check); bare "
            "service keys route every fact of a service to the KSI: "
            + ", ".join(f"{k}={v}" for k, v in bare))
