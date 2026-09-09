# Install the Fortify pre-push hook into .git/hooks.
# Git hooks are per-clone (not tracked), so each clone runs this once:
#     .\scripts\install-fortify-hook.ps1
# Remove with:  Remove-Item .git\hooks\pre-push

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$src = Join-Path $RepoRoot "scripts\hooks\pre-push"
$dstDir = Join-Path $RepoRoot ".git\hooks"
$dst = Join-Path $dstDir "pre-push"

if (-not (Test-Path $src)) { throw "Source hook not found: $src" }
if (-not (Test-Path $dstDir)) { throw "Not a git repo (no .git\hooks): $dstDir" }

Copy-Item $src $dst -Force
# Ensure the hook is executable from WSL/git-bash.
& wsl -d Ubuntu-22.04 -- bash -lc "chmod +x '$((& wsl -d Ubuntu-22.04 -- wslpath -a $dst).Trim())'" 2>$null

Write-Host "Installed pre-push hook -> $dst" -ForegroundColor Green
Write-Host "It runs the Fortify gate only when pushing main. Bypass with: git push --no-verify"
