"""Feed the botocore-derived AWS-shaped fixtures through the real collectors.

This proves the collectors ingest genuine-shape AWS responses at scale
(thousands of items) offline: no live account, deterministic, and the data
structure is AWS's own (from botocore service models via generate_fixtures.py).

Run: python -m pytest test_collectors_fixtures.py -v
Regenerate/enlarge fixtures first: python generate_fixtures.py --scale 5000
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors as c  # noqa: E402

_TESTDATA_TRACKED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")

# The fixture payloads are not committed (see .gitignore) because a large scale
# produces big files. Generate them on demand so this suite is self-sufficient
# in CI and locally: a modest default scale keeps the run fast.
#
# F-02: generation MUST NOT write into the tracked testdata/ directory. The
# runtime MANIFEST.json there is tracked, and rewriting it (with a fresh
# generated_at timestamp) dirties the worktree - which then fails the release
# attestation's clean-worktree gate after the mandatory validate suite runs. So
# when the committed payloads are absent (a clean checkout), generate into a
# throwaway temp directory and load from there; the tracked directory is never
# touched by the test run.
def _resolve_testdata(scale=1000):
    committed = os.path.join(_TESTDATA_TRACKED, "securityhub_GetFindings.json")
    if os.path.exists(committed):
        return _TESTDATA_TRACKED
    import tempfile
    import generate_fixtures as gen  # noqa: E402
    import sys as _sys
    outdir = tempfile.mkdtemp(prefix="collector-fixtures-")
    argv = _sys.argv
    _sys.argv = ["generate_fixtures.py", "--scale", str(scale), "--outdir", outdir]
    try:
        gen.main()
    finally:
        _sys.argv = argv
    return outdir


TESTDATA = _resolve_testdata()


def _load(fixture):
    with open(os.path.join(TESTDATA, fixture), encoding="utf-8") as f:
        return json.load(f)


class _StubClient:
    """A boto3-style client that returns fixture payloads for the modelled
    operations and raises for anything unexpected."""

    def __init__(self, responses):
        self._responses = responses

    def _resp(self, op, **kwargs):
        r = self._responses.get(op)
        if r is None:
            raise AssertionError(f"unexpected call: {op}")
        return r

    # Map each collector's calls to fixture-backed responses.
    def describe_hub(self, **k):
        return {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}

    def get_findings(self, **k):
        return self._resp("get_findings")

    def list_analyzers(self, **k):
        return {"analyzers": [{"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/a"}]}

    def list_findings(self, **k):
        return self._resp("list_findings")

    def list_coverage(self, **k):
        return self._resp("list_coverage")

    def list_detectors(self, **k):
        return self._resp("list_detectors")

    def get_detector(self, **k):
        return {"Status": "ENABLED"}

    def list_backup_plans(self, **k):
        return self._resp("list_backup_plans")

    def list_protected_resources(self, **k):
        return self._resp("list_protected_resources")

    def list_keys(self, **k):
        return self._resp("list_keys")

    def get_key_rotation_status(self, KeyId=None, **k):
        # deterministic: ~half rotate
        return {"KeyRotationEnabled": (hash(KeyId) % 2 == 0)}


class _StubSession:
    def __init__(self, responses):
        self._responses = responses

    def client(self, name, **k):
        return _StubClient(self._responses)


def _assert_facts_ok(facts):
    assert isinstance(facts, list) and facts, "collector must return >=1 fact"
    for f in facts:
        assert set(("service", "check", "status", "detail", "region", "collected_at")) <= set(f)
        assert len(f["detail"]) < 500, "detail must stay bounded even at scale"
        assert not f["status"].startswith("ERROR"), f"unexpected error status: {f}"


def test_security_hub_scale():
    facts = c.collect_security_hub(
        _StubSession({"get_findings": _load("securityhub_GetFindings.json")}), "us-east-1")
    _assert_facts_ok(facts)


def test_access_analyzer_scale():
    facts = c.collect_access_analyzer(
        _StubSession({"list_findings": _load("accessanalyzer_ListFindings.json")}), "us-east-1")
    _assert_facts_ok(facts)


def test_inspector_scale():
    facts = c.collect_inspector(
        _StubSession({"list_coverage": _load("inspector2_ListCoverage.json")}), "us-east-1")
    _assert_facts_ok(facts)


def test_guardduty_scale():
    facts = c.collect_guardduty(
        _StubSession({"list_detectors": _load("guardduty_ListDetectors.json")}), "us-east-1")
    _assert_facts_ok(facts)


def test_backup_scale():
    facts = c.collect_backup(
        _StubSession({
            "list_backup_plans": _load("backup_ListBackupPlans.json"),
            "list_protected_resources": _load("backup_ListProtectedResources.json"),
        }), "us-east-1")
    _assert_facts_ok(facts)


def test_kms_scale():
    facts = c.collect_kms(
        _StubSession({"list_keys": _load("kms_ListKeys.json")}), "us-east-1")
    _assert_facts_ok(facts)


def test_fixtures_are_aws_shaped():
    """Guard that the fixtures still carry authentic AWS structure."""
    sh = _load("securityhub_GetFindings.json")
    assert "Findings" in sh and "NextToken" in sh
    assert len(sh["Findings"]) >= 1000
    # A real Security Hub finding has these load-bearing fields.
    f0 = sh["Findings"][0]
    for field in ("SchemaVersion", "Id", "ProductArn", "AwsAccountId", "Types"):
        assert field in f0, f"missing genuine AWS field {field}"


def test_generation_never_dirties_tracked_testdata():
    """F-02 regression: on a clean checkout (committed payloads gitignored and
    absent) the suite MUST generate fixtures into a throwaway temp dir, never
    into the tracked testdata/ directory. Rewriting the tracked, committed
    MANIFEST.json there (with a fresh generated_at) would dirty the worktree and
    fail the release attestation's clean-worktree gate after the mandatory
    validate suite. When committed payloads are absent, resolution must point
    somewhere OTHER than the tracked dir; when they are present, using the
    tracked dir read-only is fine."""
    committed = os.path.join(_TESTDATA_TRACKED, "securityhub_GetFindings.json")
    if os.path.exists(committed):
        # Payloads committed: read-only use of the tracked dir is acceptable.
        assert TESTDATA == _TESTDATA_TRACKED
    else:
        # Clean checkout: generation must be redirected off the tracked dir.
        assert TESTDATA != _TESTDATA_TRACKED, (
            "fixtures were generated into the tracked testdata dir; this dirties "
            "the committed MANIFEST.json and breaks release attestation")
        assert not os.path.exists(committed), (
            "generation wrote a payload into the tracked testdata dir")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
