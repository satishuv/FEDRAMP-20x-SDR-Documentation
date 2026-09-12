# Versioning and releases

This framework has its own version, independent of the FedRAMP dataset version.
Never call the framework version a "FedRAMP version."

## Two versions, always both

- Framework version: semantic version of this repository's code and generators (e.g. `1.0.0`).
- CR26 dataset version: the pinned FedRAMP Consolidated Rules for 2026 release the package was built against (e.g. `2026.07.14.01`).

The release manifest (`artifacts/release-manifest.json`) records both, plus the
pinned schema versions and a SHA-256 of every generated artifact, so any release
can be reconstructed and verified.

## Release tag format

```
v<framework-version>-cr26-<dataset-version>
```

Example: `v1.0.0-cr26-2026.07.14.01`

The manifest emits this as `release_tag`. Tagging a release with this string
means: this framework version, built against this CR26 dataset, produced the
artifacts whose hashes are in the manifest.

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
