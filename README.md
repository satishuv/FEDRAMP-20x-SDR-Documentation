# FedRAMP 20x Security Decision Record (SDR) Framework

A generic, reusable framework for producing FedRAMP 20x Security Decision Records for a cloud service provider pursuing Program Certification. It covers Class A, Class B, and Class C today and carries a future-readiness register for Class D. Every requirement, Key Security Indicator (KSI), family name, and class variant derives from the canonical FedRAMP Consolidated Rules for 2026 (CR26) dataset published by FedRAMP. Nothing is hand-typed from memory.

## Who this is for

- Cloud service providers preparing a FedRAMP 20x Program Certification package at Class A, B, or C.
- Advisory and security assurance teams guiding a provider through 20x, who need a defensible, regenerable SDR rather than a hand-maintained document.
- Assessors and reviewers who want to trace every statement in an SDR back to the official dataset.

This repository is a template. It ships with a synthetic placeholder offering and honest placeholder statuses: every KSI and rule starts as Not Implemented or TBD until a real provider fills in real facts. It never claims compliance for anyone. Per-customer work belongs in separate private repositories. No customer data, credentials, account numbers, or restricted report content may ever enter this repository.

## Why it is built this way

FedRAMP 20x expects the SDR to be machine-readable, schema-valid, and backed by persistent automated verification and validation (rules FRC-CSX-VVK and FRC-CSX-VVR). A hand-edited document cannot keep up with that. This framework therefore treats the SDR as a build artifact:

1. The official CR26 dataset is pinned in the repository and hash-verified against upstream, so requirement text is always exact.
2. Humans edit exactly one file, the record store, which holds the provider's real facts.
3. A deterministic pipeline regenerates every deliverable (JSON, plain text, Word) from those two inputs.
4. A validator refuses to trust the builders: it re-derives everything from the dataset independently and fails on any mismatch.

## Quickstart

Requirements: Python 3.10 or later with the `jsonschema`, `referencing`, and `python-docx` packages.

```
pip install jsonschema referencing python-docx
```

Run the pipeline from the repository root, in this order:

| Step | Command | What it produces and why it runs here |
|------|---------|----------------------------------------|
| 1 | `python validation/scripts/build_catalogs.py` | Extracts the rule and KSI catalogs from the canonical dataset. Everything downstream reads these, so they build first. |
| 2 | `python validation/scripts/build_notes.py` | Explainer notes per rule and KSI, plus the family-name expansions. Needs the catalogs. |
| 3 | `python validation/scripts/build_profiles.py` | Per-class rule profiles, the Class C overlay, and the Class D readiness register. Needs catalogs and family names. |
| 4 | `python validation/scripts/build_sdr.py` | The official-schema JSON, its extensions companion, and the plain-text SDR for the selected class. Needs profiles, notes, and the record store. |
| 5 | `python validation/scripts/build_docx.py` | The authoring Word document for the selected class, with fill fields and guidance. |
| 6 | `python validation/scripts/build_crosswalk.py` | The NIST SP 800-53 Revision 5 to 20x KSI crosswalk, derived from the dataset's own control mappings. |
| 7 | `python validation/scripts/validate_sdr.py` | Schema validation, coverage checks, test minimums, hygiene checks, and content fidelity against the dataset. Always run last; nothing ships unless this passes with 0 hard failures. |

To change the certification class, set `certification_class` in `profiles/common/offering-profile.json` to A, B, or C, then rerun steps 4, 5, and 7.

To fill in a real provider's facts, edit only `sdr/records/records-store.json`. Every entry carries inline fill guidance: what the rule looks for, how to comply, what evidence is required, and the family spelled out in full. Then rerun steps 4, 5, and 7. Nobody edits generated outputs.

## Directory map

| Path | Contents |
|------|----------|
| `references/` | Pinned copy of the canonical CR26 dataset (hash-compare against upstream at session start) |
| `artifacts/schemas/official/` | Pinned official FedRAMP SDR and common-definitions schemas |
| `traceability/` | Derived catalogs, notes, family names, the Revision 5 crosswalk, and the AWS service to KSI map |
| `profiles/` | Per-class rule profiles, the common KSI profile, the offering profile, and the Class D future-readiness register |
| `sdr/records/` | The single editable record store |
| `sdr/json/` | Generated official-schema SDR JSON plus extensions companion, per class |
| `sdr/human-readable/` | Generated plain-text SDR and authoring Word document, per class |
| `validation/scripts/` | The pipeline |
| `validation/reports/` | Generated validation results, including per-KSI test results |
| `automation/` | Layer 1 collector registry and the read-only facts collector |
| `.claude/` | Agent guardrail rules for automated sessions working in this repository |

The `steering/` and `quality/` directories are local working notes (project charter, source register, session logs, review reports). They are excluded from the published repository by `.gitignore` because session logs carry engagement context.

## Validation

The validator (`validate_sdr.py`) checks, in order:

1. The generated JSON against the official FedRAMP SDR schema. Zero errors required.
2. Rule and KSI coverage for the selected class, in both directions (nothing missing, nothing extra).
3. Automated test minimums per FRC-CSX-VVK: Class A optional, Class B at least 1, Class C at least 2, Class D at least 4 per KSI. In template state this reports a soft failure for unfilled KSIs; that is expected, and it becomes a hard failure only at release.
4. Markdown leakage and sensitive patterns (account identifiers, access keys, private keys) across all deliverables.
5. Content fidelity: every statement, name, force, and family expansion in the generated outputs is compared against the canonical dataset through an independent resolution path, so the validator does not trust the builders it checks.

The pipeline is deterministic. Generated outputs are pinned to the dataset version and carry no run timestamps, so an unchanged dataset and record store yield byte-identical JSON, text, and CSV outputs (verified by double-run hash comparison). The Word files carry identical content but differ at the byte level across runs because the zip container embeds file-entry timestamps. To record when SDR content last changed, set `sdr_last_updated` in `profiles/common/offering-profile.json`; it feeds the official metadata block.

## Automation layer (Layer 1: deterministic collectors)

The map at `traceability/aws-service-ksi-map.json` links every KSI to example Amazon Web Services (AWS) implementation guidance with one verify method and one validate method each, matching the FRC-CSX-VVK two-method shape. From it, `build_collector_registry.py` derives `automation/collectors/registry.json`: 46 KSIs, with the AWS Config managed rules named in the guidance extracted as immediately collectable checks, and the prose methods carried as described-method entries until dedicated collectors implement them.

The collector at `automation/collectors/collect_facts.py` executes the collectable checks against an AWS account. It is read-only by construction (only `config:DescribeComplianceByConfigRule` and `sts:GetCallerIdentity`), refuses admin-looking credentials, and writes a timestamped facts store to `automation/facts/`, which is excluded from git because it identifies a real account.

Facts are telemetry, never statuses. A status changes only through deterministic checks plus human sign-off, and generative output is never deterministic telemetry, per FedRAMP's own definitions.

## Class D

The 20x Program path for Class D is listed by FedRAMP as coming in 2027, with specifics set during the 20x Phase 4 Pilot. The register at `profiles/class-d-future/readiness-register.json` shows the rules that would apply, resolved with the class d variants already present in the canonical dataset, plus a delta against Class C so a Class C provider can see exactly what tightens. It never claims Class D compliance.

## Running it as a pipeline in AWS (CI/CD for the SDR)

The `automation/pipeline/` directory contains a deployable AWS CodePipeline reference, modeled on the AWS DevSecOps pipeline pattern but with SDR-specific gates instead of SCA/SAST/DAST scanners. It lets a provider manage the SDR like production code inside their own AWS environment.

| Stage | What happens | FedRAMP rule it supports |
|-------|--------------|--------------------------|
| Source | A push to the provider's private SDR repository (GitHub via AWS CodeConnections) triggers the pipeline | CMT change management practices |
| Validate and package | CodeBuild regenerates every deliverable, fails if any generated file was hand-edited (regenerate-then-diff gate), then runs the validator with 0 hard failures required | FRC-CSX-VVR persistent automated verification and validation of the SDR |
| Human approval | SNS emails an approver; nothing publishes without sign-off | Human-gated statuses |
| Publish | Deliverables land in a versioned, encrypted S3 bucket that can back a trust center or package delivery | FRC-CSO-JSN, SDR-CSO-MTD |
| Daily drift check (scheduled) | Hash-compares the pinned dataset and schemas against fedramp.gov and alerts on change | Source currency |
| Daily collector (scheduled, opt-in) | Runs the read-only facts collector and stores timestamped facts in an evidence bucket | SDR-CSX-KMT metrics, FRC-CSX-MOT persistent validation |

Deploy with CloudFormation:

```
aws cloudformation deploy   --template-file automation/pipeline/sdr-pipeline.yaml   --stack-name sdr-pipeline   --capabilities CAPABILITY_IAM   --parameter-overrides     ConnectionArn=arn:aws:codeconnections:REGION:ACCOUNT:connection/ID     FullRepositoryId=your-org/your-sdr-repo     NotificationEmail=approver@example.com
```

Create and authorize the CodeConnections connection to your git host once in the console before deploying. The template avoids hardcoded partitions, so it works in standard and GovCloud regions. AWS CodeCommit is not used because it is closed to new customers; the source is any git host CodeConnections supports.

## Sources and verification

The canonical dataset and both official schemas are pinned in this repository and must be hash-compared against the live copies at the start of each working session, because FedRAMP updates schema files in place without renaming them. Do not cite archived pilot material (RFC-0006 era KSI counts, RFC-0024, or pre-CR26 workbooks with numeric KSI identifiers) as current requirements.

## License

MIT. See [LICENSE](LICENSE).
