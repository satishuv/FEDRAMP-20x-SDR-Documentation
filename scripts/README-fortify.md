# Fortify SCA local gate

A local pre-merge security gate using Fortify Static Code Analyzer (SCA). It
scans the automation code and infrastructure templates, applies the reviewed
suppression filter, and fails if any unaccepted finding remains.

## Why local, not in GitHub CI

Neither security scanner runs in the external repo's CI. The public CI runs
only the deterministic build and validation gate (`validate-sdr`). Both
security scanners are LOCAL pre-merge gates:

Fortify SCA cannot run on GitHub-hosted runners anyway: it is a licensed
product with a ~1 GB gated installer, and the license is tied to this machine.
ASH was previously a CI job but has been moved local as well, so security
scanning is a deliberate local step you run before committing to main, and
again on a fresh local copy of main after a merge, rather than a public-CI
check.

The split of duties:

- ASH (`scripts/ash_scan.sh` / `.ps1`) is the broad local gate (Bandit,
  checkov, detect-secrets, cdk-nag). Scope and suppressions live in `.ash.yaml`.
- Fortify (this gate) is the deeper local check. It catches dataflow and
  structural issues ASH does not.

Both are wired into the same pre-push hook, which fires only on a push to
`main`. If you later want either enforced inside GitHub, the upgrade path is a
self-hosted runner with the tool pre-installed, made a required check. That
adds operational cost (the runner must be online for any merge, and public-repo
self-hosted runners need care around forked-PR code execution), which is why
this repo runs both locally.

## What it scans

- `automation/` : all collector, prefill, metrics, AI, config-rule, and storage
  Python, plus the `pipeline/` and `config-rules/deploy/` CloudFormation
  templates.

Genuine findings are fixed in code. Reviewed false positives and intentional
design decisions are documented, with reasons, in
`.fortify/sdr-filter.txt` and suppressed by the scan.

## Run it manually

From a normal Windows PowerShell at the repo root:

```powershell
.\scripts\fortify_scan.ps1
```

Or directly inside WSL:

```bash
./scripts/fortify_scan.sh
```

Exit code `0` = clean (PASS), `1` = findings remain (FAIL), `2` = Fortify not
found. Report-only (never fail, just print the count):

```powershell
$env:FORTIFY_FAIL_ON = "0"; .\scripts\fortify_scan.ps1
```

## Make it automatic before pushing main

Install the pre-push hook once per clone (hooks are not tracked by git):

```powershell
.\scripts\install-fortify-hook.ps1
```

The hook runs both the ASH and Fortify gates only when a push updates `main`
(feature-branch pushes are not gated, since the scans are slow). Emergency
bypass:

```bash
git push --no-verify
```

## Environment overrides

| Variable         | Default                                        | Purpose                                  |
|------------------|------------------------------------------------|------------------------------------------|
| `FORTIFY_HOME`   | `/home/python/Fortify/Fortify_SCA_24.4.0`      | Fortify SCA install dir                  |
| `FORTIFY_BUILD`  | `sdr-local`                                    | SCA build id                             |
| `FORTIFY_FAIL_ON`| `1`                                            | Fail if findings >= this; `0` = report   |

## Files

- `scripts/fortify_scan.sh` : the WSL-side scanner (translate, scan, filter, count)
- `scripts/fortify_scan.ps1` : Windows wrapper that invokes the WSL scanner
- `scripts/hooks/pre-push` : the pre-push hook (gates pushes to main)
- `scripts/install-fortify-hook.ps1` : installs the hook into `.git/hooks`
- `.fortify/sdr-filter.txt` : reviewed suppressions with written justifications
