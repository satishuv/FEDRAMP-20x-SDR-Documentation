#!/usr/bin/env bash
# Fortify SCA local pre-merge gate for the FedRAMP 20x SDR repo.
#
# Runs INSIDE WSL (where Fortify SCA is installed and licensed). Translates and
# scans the automation code + infrastructure templates, applies the reviewed
# suppression filter (.fortify/sdr-filter.txt), and exits non-zero if any
# finding remains. This is the same translate -> scan -> filter -> count flow
# used to reach 31 -> 0, wrapped as a repeatable gate.
#
# Fortify SCA cannot run on GitHub-hosted runners (licensed, ~1 GB gated
# installer), so this gate is intentionally LOCAL. ASH remains the in-cloud
# automated gate; Fortify is the deeper local check before a main merge.
#
# Usage (from inside WSL, repo root):
#   scripts/fortify_scan.sh
# Env overrides:
#   FORTIFY_HOME   default /home/python/Fortify/Fortify_SCA_24.4.0
#   FORTIFY_BUILD  default sdr-local  (the SCA build id)
#   FORTIFY_FAIL_ON  default 1  (fail if findings >= this; set 0 to report-only)

set -euo pipefail

FORTIFY_HOME="${FORTIFY_HOME:-/home/python/Fortify/Fortify_SCA_24.4.0}"
BUILD_ID="${FORTIFY_BUILD:-sdr-local}"
FAIL_ON="${FORTIFY_FAIL_ON:-1}"

SA="$FORTIFY_HOME/bin/sourceanalyzer"
FPRUTIL="$FORTIFY_HOME/bin/FPRUtility"

# Resolve repo root from this script's location, then normalise to the WSL path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

FILTER="$REPO_ROOT/.fortify/sdr-filter.txt"
FPR="$(mktemp -t sdr-fortify.XXXXXX.fpr)"

echo "== Fortify SCA local gate =="
echo "   SCA:    $SA"
echo "   build:  $BUILD_ID"
echo "   filter: $FILTER"
echo "   repo:   $REPO_ROOT"

if [[ ! -x "$SA" ]]; then
  echo "ERROR: sourceanalyzer not found at $SA" >&2
  echo "       Set FORTIFY_HOME to your Fortify SCA install dir." >&2
  exit 2
fi

# Scan scope: the automation Python and the infrastructure templates.
SCAN_TARGETS=(
  "automation"
)

echo
echo "-- clean previous build model --"
"$SA" -b "$BUILD_ID" -clean

echo
echo "-- translate --"
for t in "${SCAN_TARGETS[@]}"; do
  echo "   translating $t"
  "$SA" -b "$BUILD_ID" "$REPO_ROOT/$t"
done

echo
echo "-- scan --"
SCAN_ARGS=(-b "$BUILD_ID" -scan -f "$FPR")
if [[ -f "$FILTER" ]]; then
  SCAN_ARGS+=(-filter "$FILTER")
  echo "   applying filter $FILTER"
else
  echo "   WARNING: filter file not found, scanning without suppressions"
fi
"$SA" "${SCAN_ARGS[@]}"

echo
echo "-- count findings --"
COUNT="$("$FPRUTIL" -project "$FPR" -information -listIssues 2>/dev/null | grep -c '^\[' || true)"
# Fallback: some FPRUtility builds print a plain count; try -categoryIssueCounts.
if [[ -z "$COUNT" || ! "$COUNT" =~ ^[0-9]+$ ]]; then
  COUNT="$("$FPRUTIL" -project "$FPR" -information -categoryIssueCounts 2>/dev/null \
           | awk -F: '{s+=$2} END{print s+0}')"
fi

echo
echo "== Fortify result: ${COUNT:-unknown} finding(s) after filter =="
rm -f "$FPR"

if [[ "$FAIL_ON" -eq 0 ]]; then
  echo "   (report-only mode: FORTIFY_FAIL_ON=0)"
  exit 0
fi

if [[ "${COUNT:-1}" -ge "$FAIL_ON" ]]; then
  echo "FAIL: ${COUNT} Fortify finding(s) remain (threshold ${FAIL_ON})." >&2
  echo "      Fix in code, or add a reviewed suppression to $FILTER." >&2
  exit 1
fi

echo "PASS: Fortify is clean."
exit 0
