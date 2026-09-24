# Tests for the `sdr.py init` offering-profile wizard (Max's feature).
# Uses an ISOLATED temp profile so no tracked file is mutated (audit RULE 9).
#
#   python validation/scripts/test_init_wizard.py

import json
import os
import shutil
import sys
import tempfile
import types

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _tmp_profile():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "offering-profile.json")
    shutil.copyfile(sdr.OFFERING_PROFILE, p)
    return p


def _args(**kw):
    a = types.SimpleNamespace(non_interactive=True, set=None)
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def _run_with_profile(profile_path, args):
    orig = sdr.OFFERING_PROFILE
    sdr.OFFERING_PROFILE = profile_path
    try:
        return sdr.cmd_init(args)
    finally:
        sdr.OFFERING_PROFILE = orig


def test_set_writes_fields():
    p = _tmp_profile()
    rc = _run_with_profile(p, _args(set=["organization_name=Contoso Federal",
                                         "certification_class=c"]))
    prof = json.load(open(p, encoding="utf-8"))
    check("init --set returns 0", rc == 0)
    check("organization_name written", prof["organization_name"] == "Contoso Federal")
    check("certification_class written", prof["certification_class"] == "c")


def test_invalid_class_rejected_no_write():
    p = _tmp_profile()
    before = open(p, encoding="utf-8").read()
    rc = _run_with_profile(p, _args(set=["certification_class=z"]))
    after = open(p, encoding="utf-8").read()
    check("invalid class returns non-zero", rc == 1)
    check("invalid class writes nothing", before == after)


def test_result_profile_is_valid_json():
    p = _tmp_profile()
    _run_with_profile(p, _args(set=["offering_name=Widget Cloud"]))
    try:
        json.load(open(p, encoding="utf-8"))
        ok = True
    except ValueError:
        ok = False
    check("written profile is valid JSON", ok)


def test_no_values_leaves_profile_unchanged():
    p = _tmp_profile()
    before = open(p, encoding="utf-8").read()
    rc = _run_with_profile(p, _args(set=[]))
    after = open(p, encoding="utf-8").read()
    check("no values returns 0", rc == 0)
    check("no values leaves profile byte-identical", before == after)


def main():
    for t in (test_set_writes_fields, test_invalid_class_rejected_no_write,
              test_result_profile_is_valid_json,
              test_no_values_leaves_profile_unchanged):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: init wizard ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
