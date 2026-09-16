# Versioning and releases

This framework has its own version, independent of the FedRAMP dataset version.
Never call the framework version a "FedRAMP version."

## Two versions, always both

- Framework version: semantic version of this repository's code and generators (e.g. `1.0.0`).
- CR26 dataset version: the pinned FedRAMP Consolidated Rules for 2026 release the package was built against (e.g. `2026.09.13.02`).

The release manifest (`artifacts/release-manifest.json`) records both, plus the
pinned schema versions and a SHA-256 of every generated artifact, so any release
can be reconstructed and verified. It also records a `source_provenance` block:
`requirements_sha256` and `requirements_ci_sha256` are recorded on every build;
`source_commit` and `source_tree` are recorded ONLY by a release build (they are
null in ordinary committed builds to keep the manifest diff-stable and avoid a
circular commit hash). `python sdr.py release` stamps them automatically after
the reproducibility gate passes; to stamp manually, run
`SDR_RECORD_SOURCE_COMMIT=1 python validation/scripts/build_release_manifest.py`.
Because two commits can share a framework version and dataset version, the
`source_commit` is what binds a release manifest to an exact source tree.

## Release tag format

```
v<framework-version>-cr26-<dataset-version>
```

Example: `v1.0.0-cr26-2026.09.13.02`

The manifest emits this as `release_tag`. Tagging a release with this string
means: this framework version, built against this CR26 dataset, produced the
artifacts whose hashes are in the manifest.

## Signing a release

Sign the release tag so consumers can verify it came from a trusted maintainer,
not just that a tag with the right name exists:

```
git tag -s v<framework>-cr26-<dataset> -m "FedRAMP 20x SDR framework <tag>"
git push origin v<framework>-cr26-<dataset>
```

`-s` creates a GPG-signed tag (or configure `gpg.format=ssh` / sigstore for
keyless signing per your organization's policy). Verify with
`git tag -v <tag>`. Signing keys are the maintainer's own and are never held in
this repository. A GitHub Release created from a signed tag carries the
signature badge.

## Software bill of materials (SBOM)

Every build emits a deterministic CycloneDX SBOM of the framework's own pinned
dependencies at `artifacts/sbom.cdx.json`, fingerprinted in the release manifest.
A tool that asks providers to evidence their supply chain models its own: the
SBOM lets a consumer see the exact components and versions the framework runs on
and verify them against the manifest hash.

## What a release means, and does not mean

A release passing the framework's gates means the framework release gate passed:
the package is well-formed, schema-valid, internally consistent, traceable, and
reproducible. It does NOT mean FedRAMP compliant, approved, certified, or
authorized. Those are determinations of an accredited independent assessor and
the authorizing body, never of this tool.

## Reproducibility

Generated JSON, text, and CSV carry no run timestamps and are byte-identical
across builds of unchanged inputs. CI enforces this with a double-build
reproducibility gate. Word files are the documented exception (their zip
container embeds timestamps).

## Dependencies

Runtime dependencies are pinned in `requirements.txt`; test dependencies in
`requirements-dev.txt`. GitHub Actions are pinned to full commit SHAs. This
keeps the build inputs traceable.
