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
- Nineteen additional read-only collectors in `automation/collectors/collectors.py` covering the previously described-only indicators (CloudFormation drift, Config conformance packs, WAF, security-group and network-ACL segmentation, CloudTrail and ECR integrity, S3 data protection and retention, SIEM posture, IAM just-in-time and suspicious-activity response wiring, CodePipeline gates, Inspector supply-chain scanning, and Backup restore-testing). Each is read-only (every action enumerated in the `READ_ONLY_ACTIONS` allowlist), emits posture facts rather than statuses, and is offline-testable; the collector test suite grew to 32 tests.
- `automation/config-rules/`: a provider-deployed AWS Config custom-rule scaffold (a shared, parameterized Lambda evidence-existence evaluator, a manifest of eleven rules, a deploy guide, and 6 offline handler tests) for the eleven indicators whose evidence is a document or a reviewed process rather than a live API field. These are provider infrastructure, not repository collectors; a passing result is telemetry, never a status or assessment.
- `automation/collectors/pending-ksi-classification.json`: the machine-readable triage recording which pending indicators became direct read-only collectors versus provider-deployed rules. `build_collector_registry.py` reads it so the collectable-now count regenerates deterministically.
- Five opt-in AI-assist modules in `automation/ai/` (narrative drafter, finding explainer, evidence rollup, over-claim guard, architecture-to-indicator suggester), each with an offline deterministic default backend and an opt-in Amazon Bedrock backend, a forbidden-field boundary guard, and 27 offline boundary tests wired into continuous integration.
- Compliance CAUTION banner at the top of the README: the framework is not a compliance audit bot, no generated output is compliant or guarantees FedRAMP 20x compliance, every generated statement must be independently verified by a qualified human, and AI output is advisory only.
- Continuous-integration wiring for the AI-module boundary suites and the Config custom-rule handler tests.
- Caching of the AWS Automated Security Helper install in the security-scan job, keyed to the pinned version.
- `automation/storage/provision_store.py`: a deploy-time provisioner for the durable metric-history/facts store. It creates an in-boundary S3 bucket in the provider's own account and enables bucket versioning (optionally Object Lock/WORM and a lifecycle retention). Safety-additive and idempotent — it never suspends versioning, deletes anything, or moves a status — with a DEPLOY guide and 12 offline tests wired into continuous integration.
- `docs/getting-started.md` and `docs/automation.md`: an "Adoption models" note (greenfield vs brownfield, adoption-model-agnostic) and a "Persistence and retention" note recording the 20x retention windows (KSI metric history up to one year per `SDR-CSX-KMT`; 12 months for `SCN-CSO-HIS`; 6 months for `CDS-TRC-ACL`) and clarifying that a seven-year immutable bucket is a provider policy choice, not a 20x requirement.
- Read-only `collect_bucket_versioning` collector (the read-side complement to the store provisioner): reports whether the durable store bucket has versioning enabled, as tamper-resistance/recovery telemetry. `s3:GetBucketVersioning` added to the read-only allowlist; 5 offline tests (collector suite now 37).
- `automation/config-rules/deploy/`: a deterministic generator (`generate_templates.py`) that emits both a CloudFormation template and a CDK-in-Python app for the 11 provider-deployed Config custom rules from the manifest, so the deploy artifacts never drift from it; 7 offline tests. The generated role is read-only on the evidence bucket; a COMPLIANT result stays telemetry, not a determination.
- `automation/metrics/test_metric_history_longitudinal.py`: a 420-day longitudinal test proving the SDR-CSX-KMT rollups (retention cap, up-to-one-year and last-30-day summaries, average passing fraction, same-day idempotency). It documents that the appender retains RETAIN_DAYS+1 points due to the inclusive cutoff (conservative, not data loss).
- `validation/scripts/dataset_diff.py`: an offline tool reporting which rules changed force, applicability, or statement text (plus KSI count/family changes) between two CR26 datasets; wired into the drift-check workflow so a dataset-drift review PR carries a material-changes summary. 7 offline tests.
- `automation/ai/test_bedrock_boundary.py`: boundary tests proving the drafter's forbidden-field guard still holds when a hostile or garbage non-offline (Bedrock-like) backend is behind it, injected through the existing drafter seam without changing production code.
- `examples/sample-offering/`: a fully-worked, fictional sample offering ("Acme Cloud Widgets", Class B) with a builder that swaps the sample inputs in, runs the gate to a green result (0 hard failures), and restores the real inputs. It fills narrative prose only and deliberately does not fabricate statuses, assessments, tests, or evidence, so the readiness scanner honestly reports remaining work.

### Changed

- README rewritten as an entry point rather than a reference manual. Architecture diagrams, the directory map, the validation detail, and the pipeline reference moved into `docs/`.
- Removed an unsupported claim that mapped certification classes A, B, C, and D to the Low, Moderate, and High impact levels. `FRD-CCL` describes them as assurance categories and the dataset does not state that mapping.
- Corrected three indicator names that were paraphrased rather than quoted: `KSI-CMT-LMC` is "Logging Changes", `KSI-IAM-AAM` is "Automating Account Management", and `KSI-IAM-APM` is "Adopting Passwordless Methods". The `INR` family is Incident Response, not Incident Reporting.
- License changed from MIT to all-rights-reserved, associated with Amazon Web Services (AWS) Security Assurance Services (SAS); README badge, README license section, and `CONTRIBUTING.md` updated to match. Ownership and licensing wording is pending confirmation by AWS legal.
- `docs/automation.md`, `docs/vision.md`, `docs/architecture.md`, `docs/faq.md`, `docs/README.md`, `CONTRIBUTING.md`, and `SECURITY.md` updated to reflect the built state: Layer 1 collectors call many read-only actions (not two), and Layer 2 is five built opt-in AI modules (not a single planned drafter).
- Collector coverage: thirty-five of forty-six indicators are now directly collectable read-only (up from sixteen), with the remaining eleven covered by provider-deployed Config custom rules.

### Fixed

- Corrected the described force of `FRC-CSX-VVK` across the README and `docs/getting-started.md`: automated verification of Key Security Indicators is `MAY` at Class A, `SHOULD` (at least one method per indicator) at Class B, and `MUST` at Class C (two) and Class D (four). Earlier wording implied automation was required at Class B. Verified verbatim against the FedRAMP Consolidated Rules for 2026 dataset (`2026.07.14.01`), confirmed current against the upstream `github.com/FedRAMP/rules` repository.

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
