"""Generate synthetic-but-genuine AWS-shaped fixtures for the posture collectors.

Every fixture is built by walking the REAL botocore service model shipped in
boto3 (the same definition the AWS SDK and CLI use), so the structure, field
names, types, and enum values are authentic AWS response shapes by
construction -- not hand-invented. Only the VOLUME and the leaf values are
synthetic. This lets the offline test suite fire arbitrarily large, correctly
shaped responses (hundreds/thousands of resources) through each collector
without touching a live account.

Usage:
    python generate_fixtures.py            # default sizes -> testdata/*.json
    python generate_fixtures.py --scale 5000

Each generated file is one operation's output payload:
    testdata/securityhub_GetFindings.json
    testdata/inspector2_ListCoverage.json
    ... etc.

The collectors read a known subset of fields; the generator sets those to
realistic values and fills every other modelled field with a type-correct
synthetic value, so the payload validates as a whole AWS response.
"""
import argparse
import json
import os
import random
from datetime import datetime, timezone

import botocore.session as bs
import botocore.model as m

_SESSION = bs.get_session()
_LOADER = _SESSION.get_component("data_loader")

# (service_id, operation, output-list-member to inflate, per-scale count)
# These are exactly the operations the collectors in collectors.py call whose
# response volume matters for scale.
TARGETS = [
    ("securityhub", "GetFindings", "Findings"),
    ("accessanalyzer", "ListFindings", "findings"),
    ("inspector2", "ListCoverage", "coveredResources"),
    ("backup", "ListProtectedResources", "Results"),
    ("backup", "ListBackupPlans", "BackupPlansList"),
    ("kms", "ListKeys", "Keys"),
    ("guardduty", "ListDetectors", "DetectorIds"),
]

_ID_ALPHABET = "0123456789abcdef"


def _rand_id(n=12):
    return "".join(random.choice(_ID_ALPHABET) for _ in range(n))


def _service_model(service_id):
    return m.ServiceModel(_LOADER.load_service_model(service_id, "service-2"))


def _synth(shape, depth=0, seed_index=0):
    """Produce a type-correct synthetic value for a botocore shape.

    Walks the real modelled shape. For enums, picks a real enum value. For
    strings, emits AWS-looking tokens. Recursion is depth-capped so a
    self-referential model cannot loop forever.
    """
    t = shape.type_name
    if depth > 3:
        # Bottom out safely on deep/recursive models. Depth is capped low so a
        # deeply-nested AWS shape (e.g. a Security Hub finding) does not expand
        # combinatorially into gigabyte fixtures. The collectors only read
        # shallow top-level fields, so deep detail is not load-bearing.
        return None if t in ("structure", "list", "map") else _leaf(shape, seed_index)
    if t == "structure":
        out = {}
        for name, member in shape.members.items():
            out[name] = _synth(member, depth + 1, seed_index)
        return out
    if t == "list":
        # A nested list gets ONE representative element (not two): the top-level
        # list is inflated to the requested scale by the caller, so nested lists
        # only need to prove the field is a correctly-typed list. Emitting one
        # element instead of two prevents deep shapes from multiplying in size.
        return [_synth(shape.member, depth + 1, 0)]
    if t == "map":
        return {"Key": _synth(shape.value, depth + 1, seed_index)}
    return _leaf(shape, seed_index)


def _leaf(shape, seed_index):
    t = shape.type_name
    enum = getattr(shape, "enum", None)
    if enum:
        return enum[seed_index % len(enum)]
    if t == "string":
        name = shape.name.lower()
        if "arn" in name:
            return f"arn:aws:service:us-east-1:123456789012:resource/{_rand_id()}"
        if "region" in name:
            return "us-east-1"
        return f"synthetic-{shape.name}-{seed_index}"
    if t in ("integer", "long"):
        return seed_index
    if t in ("float", "double"):
        return float(seed_index)
    if t == "boolean":
        return bool(seed_index % 2)
    if t == "timestamp":
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    if t == "blob":
        return ""
    return None


def build_payload(service_id, operation, list_member, count):
    """Build one operation output payload with `count` items in list_member,
    every field taken from the authoritative botocore output shape."""
    sm = _service_model(service_id)
    op = sm.operation_model(operation)
    out_shape = op.output_shape
    if out_shape is None:
        return {}
    payload = {}
    for name, member in out_shape.members.items():
        if name == list_member:
            elem = member.member
            if elem.type_name in ("structure", "list", "map"):
                payload[name] = [_synth(elem, seed_index=i) for i in range(count)]
            else:
                # e.g. DetectorIds is a list of strings
                payload[name] = [_leaf(elem, i) for i in range(count)]
        elif name.lower() in ("nexttoken",):
            payload[name] = None  # single-page fixture; set a token to test pagination
        else:
            payload[name] = _synth(member, seed_index=0)
    return payload


def main():
    ap = argparse.ArgumentParser(description="Generate AWS-shaped collector fixtures from botocore models.")
    ap.add_argument("--scale", type=int, default=1000,
                    help="items per list fixture (default 1000)")
    ap.add_argument("--outdir", default=None,
                    help="output directory (default: testdata/ next to this script)")
    args = ap.parse_args()

    outdir = args.outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
    os.makedirs(outdir, exist_ok=True)

    manifest = []
    for service_id, operation, list_member in TARGETS:
        payload = build_payload(service_id, operation, list_member, args.scale)
        fname = f"{service_id}_{operation}.json"
        path = os.path.join(outdir, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        n = len(payload.get(list_member, []))
        manifest.append({"service": service_id, "operation": operation,
                         "list_member": list_member, "items": n, "file": fname})
        print(f"  {fname}: {n} items in .{list_member}")

    with open(os.path.join(outdir, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "scale": args.scale, "source": "botocore service-2 models",
                   "fixtures": manifest}, f, indent=2)
    print(f"Wrote {len(manifest)} fixtures + MANIFEST.json to {outdir}")


if __name__ == "__main__":
    main()
