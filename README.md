FedRAMP 20x Security Decision Record (SDR) Framework

A generic, reusable framework for producing FedRAMP 20x Security Decision Records for a cloud service provider pursuing Program Certification. It covers Class A, Class B, and Class C today and carries a future-readiness register for Class D. Every requirement, Key Security Indicator (KSI), family name, and class variant derives from the canonical FedRAMP Consolidated Rules for 2026 (CR26) dataset published by FedRAMP; nothing is hand-typed from memory.

1. What this is and is not

This repository is a template. It ships with a synthetic placeholder offering ("Example PaaS Foundation") and honest placeholder statuses: every KSI and rule starts as Not Implemented or TBD until a real provider fills in real facts. It never claims compliance for anyone. Per-customer work belongs in separate private repositories; no customer data, credentials, account numbers, or restricted report content may ever enter this repository.

2. How the framework works

The only file a human edits is sdr/records/records-store.json. Every entry in it carries inline fill_guidance: what the rule or KSI looks for, how to comply, what evidence is required, and the rule or KSI family spelled out in full. The pipeline regenerates everything else. Nobody edits generated outputs.

Requirements: Python 3.10 or later with the jsonschema, referencing, and python-docx packages (pip install jsonschema referencing python-docx).

Pipeline order, run from the repository root:

1. python validation/scripts/build_catalogs.py (extracts rule and KSI catalogs from the canonical dataset)
2. python validation/scripts/build_notes.py (explainer notes per rule and KSI, family names)
3. python validation/scripts/build_profiles.py (per-class rule profiles, Class C overlay, Class D readiness register)
4. python validation/scripts/build_sdr.py (official-schema JSON, extensions companion, plain-text SDR for the selected class)
5. python validation/scripts/build_docx.py (authoring docx for the selected class)
6. python validation/scripts/build_crosswalk.py (NIST SP 800-53 Revision 5 to 20x KSI crosswalk)
7. python validation/scripts/validate_sdr.py (schema validation, coverage checks, test minimums, hygiene checks)

Select the certification class by setting certification_class in profiles/common/offering-profile.json to A, B, or C, then rerun steps 4, 5, and 7.

3. Directory map

- references/ pinned copy of the canonical CR26 dataset (hash-compare against upstream at session start)
- artifacts/schemas/official/ pinned official FedRAMP SDR and common-definitions schemas
- traceability/ derived catalogs, notes, family names, and the Revision 5 crosswalk
- profiles/ per-class rule profiles, the common KSI profile, the offering profile, and the Class D future-readiness register
- sdr/records/ the single editable record store
- sdr/json/ generated official-schema SDR JSON plus extensions companion per class
- sdr/human-readable/ generated plain-text SDR and authoring docx per class
- validation/scripts/ the pipeline
- validation/reports/ generated validation results, including per-KSI test results
- .claude/ agent guardrail rules for automated sessions working in this repository
- quality/ and steering/ local working notes (review reports, project charter, source register, session state); excluded from the published repository by .gitignore because session logs carry engagement context

4. Validation

validate_sdr.py checks the generated JSON against the official FedRAMP SDR schema (0 errors required), verifies rule and KSI coverage for the selected class, checks automated test minimums per FRC-CSX-VVK (Class A optional, Class B at least 1, Class C at least 2, Class D at least 4 per KSI), scans for markdown leakage and sensitive patterns, and verifies content fidelity: every statement, name, force, and family expansion in the generated outputs is compared against the canonical dataset with an independent resolution path, so the validator does not trust the builders it checks. In template state the test-minimum check reports a soft failure for unfilled KSIs; that is expected and becomes a hard failure only at release.

The pipeline is deterministic: generated outputs are pinned to the dataset version and carry no run timestamps, so an unchanged dataset and record store yield byte-identical JSON, text, and CSV outputs (verified by double-run hash comparison). The docx files carry identical content but differ at the byte level across runs because the zip container embeds file-entry timestamps. To record when SDR content last changed, set sdr_last_updated in profiles/common/offering-profile.json; it feeds the official metadata block.

5. Sources and verification

The controlling sources are listed in steering/source-register.txt. The canonical dataset and both official schemas are pinned in this repository and must be hash-compared against the live copies at the start of each working session, because FedRAMP updates schema files in place without renaming them. Do not cite archived pilot material (RFC-0006 era KSI counts, RFC-0024) as current requirements.

6. Class D

The 20x Program path for Class D is listed by FedRAMP as coming in 2027, with specifics set during the 20x Phase 4 Pilot. profiles/class-d-future/readiness-register.json shows the rules that would apply, resolved with the class d variants already present in the canonical dataset, plus a delta against Class C. It never claims Class D compliance.

7. License

MIT. See LICENSE.
