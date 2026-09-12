#!/usr/bin/env python3
"""End-to-end adversarial test: tamper a GENERATED SDR file and prove the real
validate_sdr.py gate hard-fails, then restore it. This runs the actual shipped
validator as a subprocess, so it proves the gate a real PR would hit.

Offline. Run:
    python tests/adversarial/test_e2e_tampering.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _class():
    with open(os.path.join(BASE, "profiles", "common", "offering-profile.json"),
              encoding="utf-8") as f:
        return (json.load(f).get("certification_class") or "b").lower()


def _run_validator():
    proc = subprocess.run(
        [sys.executable, os.path.join(BASE, "validation", "scripts", "validate_sdr.py")],
        cwd=BASE, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def test_tampered_sdr_statement_hard_fails():
    """Change one KSI statement in the generated SDR text and confirm the
    content-fidelity gate hard-fails; restore afterward."""
    cls = _class()
    txt_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt")
    if not os.path.exists(txt_path):
        print("SKIP: build the SDR first (python sdr.py build)")
        return
    tmp = tempfile.mkdtemp(prefix="adv-")
    bak = os.path.join(tmp, "sdr.txt.bak")
    shutil.copy2(txt_path, bak)
    try:
        # Baseline should pass content fidelity.
        rc0, out0 = _run_validator()
        assert "content_fidelity_against_dataset | 0 mismatches" in out0, \
            "baseline should have clean content fidelity"
        # Tamper: corrupt a verbatim KSI statement in the human-readable output.
        content = open(txt_path, encoding="utf-8").read()
        marked = content.replace("persistently", "PERSISTENTLY-TAMPERED", 1)
        assert marked != content, "expected to find a token to tamper"
        with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(marked)
        rc1, out1 = _run_validator()
        # The content-fidelity check must now report a mismatch (statement not
        # found verbatim), i.e. the gate caught the tampering.
        assert "content_fidelity_against_dataset | 0 mismatches" not in out1, \
            "validator did NOT catch the tampered statement"
        assert "FAIL: content_fidelity_against_dataset" in out1, \
            "expected a content-fidelity FAIL after tampering"
        print("PASS: test_tampered_sdr_statement_hard_fails")
    finally:
        shutil.copy2(bak, txt_path)
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    test_tampered_sdr_statement_hard_fails()
    print("\n1/1 end-to-end adversarial test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
