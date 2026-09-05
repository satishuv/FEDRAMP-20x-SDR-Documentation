Non-negotiable guardrails for any agent session in this repository. These restate and extend CLAUDE.md; where they overlap, both apply.

1. Source of truth: references/fedramp-consolidated-rules.json (the FedRAMP Consolidated Rules for 2026 (CR26) dataset) and the pinned official schemas in artifacts/schemas/official/. Verify both against live upstream by hash at session start and record the check in steering/source-register.txt.
2. Never fabricate compliance facts. Statuses only move on real evidence plus human sign-off. Generative output is never deterministic telemetry and never flips a status to Implemented.
3. Never commit or push without the owner's explicit instruction, and never before validate_sdr.py reports 0 hard failures for every class being shipped.
4. Never add customer-identifying material to this repository. Per-customer work happens in separate private repositories.
5. Edit only sdr/records/records-store.json and the pipeline scripts; regenerate everything else. Generated files are build outputs, not documents.
