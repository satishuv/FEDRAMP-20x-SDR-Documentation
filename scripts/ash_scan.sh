#!/usr/bin/env bash
# ASH (AWS Automated Security Helper) local pre-merge gate.
#
# ASH no longer runs in the external repo's CI; it is a LOCAL gate you run
# before committing or pushing to main, and again on a fresh local copy of
# main after a merge. This mirrors the Fortify local gate. Run from the repo
# root:
#     scripts/ash_scan.sh
#
# Report-only (do not fail on findings):
#     ASH_FAIL_ON=0 scripts/ash_scan.sh
#
# Requires ASH installed and on PATH. Install once (pinned version):
#     pip install "git+https://github.com/awslabs/automated-security-helper.git@v3.0.0" "pydantic>=2.11.3,<2.12"
#
# Scan scope and suppressions live in .ash.yaml. Findings at or above the
# configured severity threshold (.ash.yaml global_settings.severity_threshold)
# cause a non-zero exit.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

FAIL_ON="${ASH_FAIL_ON:-1}"
OUT_DIR=".ash/ash_output"

if ! command -v ash >/dev/null 2>&1; then
  echo "[ash] ERROR: 'ash' is not on PATH. Install it with:" >&2
  echo "      pip install \"git+https://github.com/awslabs/automated-security-helper.git@v3.0.0\" \"pydantic>=2.11.3,<2.12\"" >&2
  exit 2
fi

echo "[ash] running ASH scan (local mode) on $REPO_ROOT"
set +e
ash scan --source-dir . --output-dir "$OUT_DIR" --mode local
code=$?
set -e

echo "[ash] reports written to $OUT_DIR/reports/"

if [[ "$FAIL_ON" == "0" ]]; then
  echo "[ash] report-only mode (ASH_FAIL_ON=0); not gating on exit code $code"
  exit 0
fi

if [[ "$code" -eq 0 ]]; then
  echo "[ash] gate: PASS"
else
  echo "[ash] gate: FAIL (exit $code). See $OUT_DIR/reports/ for actionable findings."
fi
exit "$code"
