#!/usr/bin/env python3
"""Offline regression for publish_history.py (AUD-F20): the durable metric
history is written with a compare-and-swap, never a blind overwrite, and every
run's observations are archived append-only.

A fake S3 client models exactly the two conditional-write behaviours the code
relies on: PutObject with IfMatch fails 412 when the stored ETag differs, and
PutObject with IfNoneMatch="*" fails 412 when the key exists.

    python automation/metrics/test_publish_history.py
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import publish_history as ph  # noqa: E402

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


class S3Error(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class _Body:
    def __init__(self, b):
        self._b = b

    def read(self):
        return self._b


class FakeS3:
    """Versioned-object model: objects[key] = (bytes, etag). ETags are
    monotonic counters so a change is always visible."""
    def __init__(self):
        self.objects = {}
        self._n = 0
        self.puts = []

    def _etag(self):
        self._n += 1
        return f'"etag-{self._n}"'

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise S3Error("NoSuchKey", 404)
        body, etag = self.objects[Key]
        return {"Body": _Body(body), "ETag": etag}

    def put_object(self, Bucket, Key, Body, IfMatch=None, IfNoneMatch=None, **_kw):
        self.puts.append({"Key": Key, "IfMatch": IfMatch, "IfNoneMatch": IfNoneMatch})
        if IfNoneMatch == "*" and Key in self.objects:
            raise S3Error("PreconditionFailed", 412)
        if IfMatch is not None and (Key not in self.objects or self.objects[Key][1] != IfMatch):
            raise S3Error("PreconditionFailed", 412)
        etag = self._etag()
        self.objects[Key] = (Body, etag)
        return {"ETag": etag}


def _history(observed_at, passing):
    return {"meta": {"last_observed_at": observed_at, "dataset_version": "t"},
            "ksis": {"KSI-X": {
                "series": [{"date": observed_at[:10], "passing": passing, "total": 10}],
                "observations": [{"observed_at": observed_at, "date": observed_at[:10],
                                  "passing": passing, "total": 10}]}}}


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def main():
    tmp = tempfile.mkdtemp(prefix="ph-")
    hist = os.path.join(tmp, "metric-history.json")
    etag = hist + ".etag"
    logs = []
    log = logs.append

    # First run: nothing in the bucket. restore -> confirmed missing; publish
    # must be create-only (IfNoneMatch) and succeed.
    s3 = FakeS3()
    check("restore on a missing object is a clean first run",
          ph.restore(s3, "b", hist, etag, log=log) == ph.EXIT_OK)
    _write(hist, _history("2026-09-25T06:00:00+00:00", 3))
    rc = ph.publish(s3, "b", hist, etag, run_id="run1", log=log)
    check("first publish succeeds", rc == ph.EXIT_OK, f"rc={rc} {logs[-1:]}")
    hist_puts = [p for p in s3.puts if p["Key"] == ph.HISTORY_KEY]
    check("first publish was create-only (IfNoneMatch=*)",
          hist_puts and hist_puts[-1]["IfNoneMatch"] == "*", str(hist_puts))
    obs_keys = [k for k in s3.objects if k.startswith(ph.OBSERVATIONS_PREFIX)]
    check("run observations archived under metrics/observations/<date>/<run>.json",
          obs_keys == ["metrics/observations/2026-09-25/run1.json"], str(obs_keys))
    archived = json.loads(s3.objects[obs_keys[0]][0])
    check("archived record carries only this run's observations",
          archived["run_id"] == "run1" and archived["ksis"]["KSI-X"][0]["passing"] == 3)

    # Second run, no interference: restore records the ETag, publish uses IfMatch.
    logs.clear()
    check("restore of an existing object succeeds",
          ph.restore(s3, "b", hist, etag, log=log) == ph.EXIT_OK)
    with open(etag, encoding="utf-8") as f:
        remembered = f.read().strip()
    check("restore remembered the object's ETag",
          remembered == s3.objects[ph.HISTORY_KEY][1], remembered)
    _write(hist, _history("2026-09-25T18:00:00+00:00", 9))
    rc = ph.publish(s3, "b", hist, etag, run_id="run2", log=log)
    check("uncontended publish succeeds with IfMatch",
          rc == ph.EXIT_OK and s3.puts[-1]["IfMatch"] == remembered, f"rc={rc} {s3.puts[-1]}")

    # Third run RACES a concurrent writer: between restore and publish another
    # run replaces the object. The CAS must refuse (exit 3), leaving the other
    # writer's history intact, and our observations still archived.
    logs.clear()
    ph.restore(s3, "b", hist, etag, log=log)
    other = json.dumps(_history("2026-09-25T20:00:00+00:00", 1)).encode()
    s3.put_object("b", ph.HISTORY_KEY, other)  # concurrent writer wins the race
    winner_etag = s3.objects[ph.HISTORY_KEY][1]
    _write(hist, _history("2026-09-25T21:00:00+00:00", 10))
    rc = ph.publish(s3, "b", hist, etag, run_id="run3", log=log)
    check("contended publish returns EXIT_CONFLICT (3), not success",
          rc == ph.EXIT_CONFLICT, f"rc={rc} {logs[-1:]}")
    check("the concurrent writer's history was NOT overwritten",
          s3.objects[ph.HISTORY_KEY] == (other, winner_etag))
    check("the losing run's observations were still archived (append-only)",
          "metrics/observations/2026-09-25/run3.json" in s3.objects)

    # Retry of the SAME run after re-restore: the observation object already
    # exists (same run id) and must be kept, not overwritten, and the history
    # CAS now succeeds against the winner's ETag.
    logs.clear()
    ph.restore(s3, "b", hist, etag, log=log)
    _write(hist, _history("2026-09-25T21:05:00+00:00", 10))
    before = s3.objects["metrics/observations/2026-09-25/run3.json"]
    rc = ph.publish(s3, "b", hist, etag, run_id="run3", log=log)
    check("retry after re-restore publishes successfully", rc == ph.EXIT_OK, f"rc={rc}")
    check("retry kept the first immutable observation record byte-for-byte",
          s3.objects["metrics/observations/2026-09-25/run3.json"] == before)

    # Restore fails closed on a non-missing error.
    class Denied(FakeS3):
        def get_object(self, Bucket, Key):
            raise S3Error("AccessDenied", 403)
    check("restore fails closed on AccessDenied (not treated as first run)",
          ph.restore(Denied(), "b", hist, etag, log=log) == ph.EXIT_ERROR)

    # Every history PUT the publisher ever issued was conditional.
    unconditional = [p for p in s3.puts
                     if p["Key"] == ph.HISTORY_KEY and p["IfMatch"] is None
                     and p["IfNoneMatch"] is None and p is not None]
    # (the one unconditional put above was the simulated concurrent writer)
    check("publisher never issued an unconditional history PUT",
          len(unconditional) == 1, str(unconditional))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: publish_history ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
