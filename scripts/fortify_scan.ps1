# Fortify SCA local pre-merge gate - Windows wrapper.
#
# Invokes the WSL-side scanner (scripts/fortify_scan.sh) since Fortify SCA is
# installed under WSL. Run from a normal PowerShell at the repo root:
#     powershell -ExecutionPolicy Bypass -File scripts\fortify_scan.ps1
# or just:
#     .\scripts\fortify_scan.ps1
#
# Passes through the exit code so it works as a gate. Report-only:
#     $env:FORTIFY_FAIL_ON = "0"; .\scripts\fortify_scan.ps1

param(
    [string]$Distro = "Ubuntu-22.04"
)

$ErrorActionPreference = "Stop"

# Repo root = parent of this script's directory.
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Translate the Windows repo path to the WSL /mnt/... path.
$WslRepo = (& wsl -d $Distro -- wslpath -a ("{0}" -f $RepoRoot)).Trim()

Write-Host "Running Fortify gate in WSL ($Distro)..." -ForegroundColor Cyan
Write-Host "  repo (wsl): $WslRepo"

# Forward the fail-on override if set.
$FailOn = if ($env:FORTIFY_FAIL_ON) { $env:FORTIFY_FAIL_ON } else { "1" }

& wsl -d $Distro -- bash -lc "FORTIFY_FAIL_ON='$FailOn' '$WslRepo/scripts/fortify_scan.sh'"
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Host "Fortify gate: PASS" -ForegroundColor Green
} else {
    Write-Host "Fortify gate: FAIL (exit $code)" -ForegroundColor Red
}
exit $code
