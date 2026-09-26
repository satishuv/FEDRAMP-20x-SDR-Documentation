#!/usr/bin/env python3
"""Offline tests for update_sources_lock.py using a throwaway repo layout (tiny
synthetic dataset and schema files; no network). Run:
    python validation/scripts/test_update_sources_lock.py

The lock is the human-readable record of what every pin means. These tests pin
the updater's contract: it refreshes EVERY pinned entry from the file on disk
(sha256, and $schemaVersion for JSON schemas), it is idempotent, it fails closed
on a missing pinned file instead of writing a lock that vouches for nothing, and
it never claims "verified current against upstream" unless the caller asserts
the date explicitly.
"""

import collections
import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import update_sources_lock as usl  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class _Repo:
    """Temporary repo root with references/ + artifacts/schemas/official/."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="usl-test-")
        self.dataset = json.dumps({"info": {"version": "2026.01.01.01"}}).encode()
        _write(os.path.join(self.root, "references", "fedramp-consolidated-rules.json"), self.dataset)
        self.rules_schema = b'{"$schema": "x", "title": "rules"}'
        _write(os.path.join(self.root, "references", "fedramp-consolidated-rules.schema.json"),
               self.rules_schema)
        self.common_old = json.dumps({"$id": "common", "$schemaVersion": "0.3.0"}).encode()
        self.common_rel = "artifacts/schemas/official/common.json"
        _write(os.path.join(self.root, self.common_rel), self.common_old)
        self.plain = b'{"not_a_schema": true}'
        self.plain_rel = "artifacts/schemas/official/plain.json"
        _write(os.path.join(self.root, self.plain_rel), self.plain)
        self.lock = collections.OrderedDict([
            ("verified_current_on", "2026-01-01"),
            ("sources", collections.OrderedDict([
                ("cr26_consolidated_rules", {"version": "old", "sha256": "0" * 64,
                                             "pinned_path": "references/fedramp-consolidated-rules.json"}),
                ("cr26_rules_schema", {"sha256": "0" * 64,
                                       "pinned_path": "references/fedramp-consolidated-rules.schema.json"}),
                ("common_definitions_schema", {"schema_version": "0.3.0", "sha256": _sha(self.common_old),
                                               "pinned_path": self.common_rel}),
                ("plain_pinned", {"schema_version": "keep-me", "sha256": _sha(self.plain),
                                  "pinned_path": self.plain_rel}),
                ("no_pin", {"description": "informational only, no pinned_path"}),
            ])),
        ])

    def point_module_here(self):
        usl.BASE = self.root
        usl.DATASET = os.path.join(self.root, "references", "fedramp-consolidated-rules.json")
        usl.LOCK = os.path.join(self.root, "references", "sources.lock.json")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _with_repo(fn):
    repo = _Repo()
    saved = (usl.BASE, usl.DATASET, usl.LOCK)
    try:
        repo.point_module_here()
        fn(repo)
    finally:
        usl.BASE, usl.DATASET, usl.LOCK = saved
        repo.cleanup()


def test_dataset_and_rules_schema_refreshed_from_disk():
    def body(repo):
        changes = usl.refresh_lock(repo.lock, upstream_commit="abc123")
        ds = repo.lock["sources"]["cr26_consolidated_rules"]
        assert ds["version"] == "2026.01.01.01", ds
        assert ds["sha256"] == _sha(repo.dataset)
        assert ds["upstream_commit"] == "abc123"
        rs = repo.lock["sources"]["cr26_rules_schema"]
        assert rs["sha256"] == _sha(repo.rules_schema)
        assert rs["upstream_commit"] == "abc123"
        assert any(c.startswith("cr26_consolidated_rules version") for c in changes), changes
    _with_repo(body)


def test_schema_entry_hash_and_version_follow_the_file_on_disk():
    def body(repo):
        new = json.dumps({"$id": "common", "$schemaVersion": "0.4.0",
                          "$defs": {"contactInformation": {}}}).encode()
        _write(os.path.join(repo.root, repo.common_rel), new)
        changes = usl.refresh_lock(repo.lock)
        ent = repo.lock["sources"]["common_definitions_schema"]
        assert ent["sha256"] == _sha(new), ent
        assert ent["schema_version"] == "0.4.0", ent
        assert any("common_definitions_schema schema_version 0.3.0 -> 0.4.0" == c for c in changes), changes
        assert any(c.startswith("common_definitions_schema sha256") for c in changes), changes
    _with_repo(body)


def test_non_schema_pinned_file_keeps_its_version_field():
    def body(repo):
        usl.refresh_lock(repo.lock)
        ent = repo.lock["sources"]["plain_pinned"]
        # No $schemaVersion in the file: the hash is refreshed, the version field
        # is left exactly as recorded (never blanked or invented).
        assert ent["schema_version"] == "keep-me", ent
        assert ent["sha256"] == _sha(repo.plain)
    _with_repo(body)


def test_idempotent_second_run_reports_no_change():
    def body(repo):
        usl.refresh_lock(repo.lock)
        snapshot = json.dumps(repo.lock, sort_keys=True)
        changes = usl.refresh_lock(repo.lock)
        assert changes == [], changes
        assert json.dumps(repo.lock, sort_keys=True) == snapshot
    _with_repo(body)


def test_missing_pinned_file_fails_closed():
    def body(repo):
        os.remove(os.path.join(repo.root, repo.common_rel))
        try:
            usl.refresh_lock(repo.lock)
        except FileNotFoundError as e:
            assert "common_definitions_schema" in str(e), e
        else:
            raise AssertionError("a missing pinned file must not produce a lock")
    _with_repo(body)


def test_verified_on_is_asserted_only_by_the_caller():
    def body(repo):
        usl.refresh_lock(repo.lock)
        assert repo.lock["verified_current_on"] == "2026-01-01", "must not self-stamp"
        try:
            usl.refresh_lock(repo.lock, verified_on="not-a-date")
        except ValueError:
            pass
        else:
            raise AssertionError("malformed --verified-on must be rejected")
        changes = usl.refresh_lock(repo.lock, verified_on="2026-09-26")
        assert repo.lock["verified_current_on"] == "2026-09-26"
        assert "verified_current_on -> 2026-09-26" in changes, changes
    _with_repo(body)


def test_main_writes_lock_file_and_returns_zero():
    def body(repo):
        with open(usl.LOCK, "w", encoding="utf-8", newline="\n") as f:
            json.dump(repo.lock, f, indent=1)
        new = json.dumps({"$id": "common", "$schemaVersion": "0.9.9"}).encode()
        _write(os.path.join(repo.root, repo.common_rel), new)
        assert usl.main(["--verified-on", "2026-09-26"]) == 0
        written = json.load(open(usl.LOCK, encoding="utf-8"))
        assert written["sources"]["common_definitions_schema"]["schema_version"] == "0.9.9"
        assert written["sources"]["common_definitions_schema"]["sha256"] == _sha(new)
        assert written["verified_current_on"] == "2026-09-26"
    _with_repo(body)


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
