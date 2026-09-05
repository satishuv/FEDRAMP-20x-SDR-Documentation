Guidance for Claude Code sessions working in this repository.

What this repository is: a generic, reusable framework for producing FedRAMP 20x Security Decision Records (SDRs). Everything derives from the canonical FedRAMP Consolidated Rules for 2026 (CR26) dataset pinned in references/. Read README.md first. If the local-only steering/ directory is present (it is excluded from the published repository), also read steering/source-register.txt and steering/session-state.txt for the current state of work.

Hard rules, no exceptions:

1. No fabrication. Missing facts are labeled TBD, Needs validation, Not applicable with justification, Planned, Gap, Exception, or FedRAMP pending. Never mark anything Implemented without real evidence.
2. No customer data, credentials, account numbers, internal endpoints, or restricted report content in any artifact. Synthetic examples only, always labeled as examples.
3. Every FedRAMP or Amazon Web Services (AWS) fact is checked against the sources in steering/source-register.txt, never asserted from memory. At session start, hash-compare references/fedramp-consolidated-rules.json and the pinned schemas in artifacts/schemas/official/ against the live copies; FedRAMP updates schema files in place without renaming them.
4. The only human-editable content file is sdr/records/records-store.json. Never hand-edit generated outputs (traceability/, profiles/, sdr/json/, sdr/human-readable/, validation/reports/). Change the pipeline or the record store, then regenerate.
5. Human-readable deliverables are clean plain text: numbered headings, consistent labels, no markdown symbols inside deliverable content.
6. JSON deliverables must validate against the official FedRAMP SDR schema with 0 errors. Provider extras live only in the isolated providerExtensions object and the extensions companion file.
7. All validation must pass (0 hard failures) before any commit. Run the full pipeline in order: build_catalogs, build_notes, build_profiles, build_sdr, build_docx, build_crosswalk, validate_sdr.
8. Do not cite archived pilot material (RFC-0006 era KSI counts, RFC-0024, pre-CR26 workbooks with numeric KSI identifiers such as KSI-IAM-01) as current requirements.

Pipeline and class selection: set certification_class in profiles/common/offering-profile.json (A, B, or C), then run build_sdr.py, build_docx.py, and validate_sdr.py. Scripts resolve all paths relative to their own location; do not reintroduce absolute paths.

Verified anchor numbers (recheck against the dataset if it changes): 234 rules extracted; 46 KSIs in 10 families; provider profiles resolve to 41 rules and 7 KSIs at Class A (enumerated by FRC-CLA-MFR, not blanket), 158 rules and 46 KSIs at Class B and Class C; 157 rules in the Class D readiness register; 5 KSIs have empty statements in the official dataset and are carried as FedRAMP pending; FRC-CSX-VVK test minimums are A 0, B 1, C 2, D 4.
