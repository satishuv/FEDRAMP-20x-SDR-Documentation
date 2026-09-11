# ASH (AWS Automated Security Helper) local pre-merge gate - Windows wrapper.
#
# ASH no longer runs in the external repo's CI; run it locally before
# committing or pushing to main, and again on a fresh local copy of main after
# a merge. Run from a normal PowerShell at the repo root:
#     powershell -ExecutionPolicy Bypass -File scripts\ash_scan.ps1
# or just:
#     .\scripts\ash_scan.ps1
#
# Report-only (do not fail on findings):
#     $env:ASH_FAIL_ON = "0"; .\scripts\ash_scan.ps1
#
# ASH runs on Linux, so this wrapper invokes the WSL-side scanner
# (scripts/ash_scan.sh), matching how the Fortify wrapper works. Requires ASH
# installed inside the WSL distro and on PATH there.

param(
    [string]$Distro = "Ubuntu-22.04"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$WslRepo = (& wsl -d $Distro -- wslpath -a ("{0}" -f $RepoRoot)).Trim()

Write-Host "Running ASH gate in WSL ($Distro)..." -ForegroundColor Cyan
Write-Host "  repo (wsl): $WslRepo"

$FailOn = if ($env:ASH_FAIL_ON) { $env:ASH_FAIL_ON } else { "1" }

& wsl -d $Distro -- bash -lc "ASH_FAIL_ON='$FailOn' '$WslRepo/scripts/ash_scan.sh'"
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Host "ASH gate: PASS" -ForegroundColor Green
} else {
    Write-Host "ASH gate: FAIL (exit $code)" -ForegroundColor Red
}
exit $code
