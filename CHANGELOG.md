# Changelog

Notable changes to this project. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

One project-specific convention: the pinned FedRAMP dataset version is recorded alongside every release, because the same code against a different dataset produces a different record.

## Unreleased

Pinned dataset: `2026.07.14.01`

### Added

- Documentation restructured into `docs/`: getting started, implementation guide, architecture, certification classes, validation and readiness, continuous integration, automation layers, glossary, frequently asked questions, vision and mission.
- `sdr.py` orchestrator with `build`, `validate`, `scan`, `all`, and `clean` subcommands, so a first run is one command instead of seven.
- `Makefile` with equivalent targets.
- Community health files: contributing guide, security policy, code of conduct, this changelog, issue templates, pull request template.

### Changed

- README rewritten as an entry point rather than a reference manual. Architecture diagrams, the directory map, the validation detail, and the pipeline reference moved into `docs/`.
- Removed an unsupported claim that mapped certification classes A, B, C, and D to the Low, Moderate, and High impact levels. `FRD-CCL` describes them as assurance categories and the dataset does not state that mapping.
- Corrected three indicator names that were paraphrased rather than quoted: `KSI-CMT-LMC` is "Logging Changes", `KSI-IAM-AAM` is "Automating Account Management", and `KSI-IAM-APM` is "Adopting Passwordless Methods". The `INR` family is Incident Response, not Incident Reporting.

## 0.1.0, 2026-09-05

First working version. Pinned dataset: `2026.07.14.01`.

### Added

- Pinned canonical sources: the CR26 dataset and both official FedRAMP schemas, hash-verified against upstream.
- Seven-step deterministic pipeline: catalogs, notes, profiles, record, Word output, crosswalk, validation.
- Traceability layer: derived rule and indicator catalogs, per-rule notes, family name expansions, and the NIST SP 800-53 Revision 5 to 20x crosswalk.
- Per-class profiles for Classes A, B, and C, the Class C overlay, and the Class D readiness register at 157 rules with a delta against Class C.
- Deliverables for each class: official schema JSON, an isolated provider extensions companion, plain text, and an authoring Word file.
- `validate_sdr.py`, the build gate: eight checks including schema validation, bidirectional coverage, per-class automated-method minimums, secret scanning, and content fidelity re-derived from the dataset through an independent code path.
- `sdrscan.py`, the readiness scanner: 37 checks emitting one finding per rule and per indicator, each citing the governing rule, in five output formats.
- AWS service to indicator map with one verify and one validate method per indicator, matching the `FRC-CSX-VVK` two-method shape.
- Layer 1 facts collector, read-only by construction: two API calls, refuses administrative-looking credentials, writes a git-excluded timestamped facts store.
- GitHub Actions workflows for the validation gate and a daily upstream drift check, with actions pinned to full commit SHAs.
- Deployable AWS CodePipeline reference with the same gates, human approval before publication, and scheduled drift and collection stages.
- Agent guardrails in `.claude/` for automated sessions.

### Fixed

- Every text writer and git blob pinned to LF line endings, so regeneration in continuous integration is byte-stable across platforms.

## Notes on versioning

A change to the pinned dataset is at least a minor version, because generated deliverables change even when no code does. A change that alters what the validator accepts or rejects is a major version, because it can invalidate a record a provider has already built and shipped.
