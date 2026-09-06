# Vision and mission

## Mission

Make a FedRAMP 20x Security Decision Record something a provider can generate, verify, and defend in an afternoon, instead of something a consultant assembles over months and nobody can trace.

## Vision

Authorization artifacts should be built the way software is built. Pinned inputs, a deterministic pipeline, a validator that does not trust the thing it validates, and a diff that shows exactly what changed and why. If that becomes normal, three things follow:

1. An assessor can trace any sentence in a record back to the rule that required it, in one hop, without asking anyone.
2. A provider learns about a FedRAMP requirement change from a failing build, not from a finding during assessment.
3. The cost of a first authorization stops being a barrier that only large vendors can clear.

## Principles

These are the decisions that shaped the code, in the order they get applied when they conflict.

**Truth over convenience.** Requirement text is resolved from the canonical dataset at build time and compared against it again at validation time, through an independent code path. Nothing is transcribed by hand. When the framework does not know something, it says `TBD` rather than guessing, because a plausible guess in an authorization package is worse than an obvious hole.

**One editable surface.** Humans edit `sdr/records/records-store.json`. Everything else is a build output. This is the single design choice that makes the rest possible: there is exactly one place where a fact can enter, so there is exactly one place to review.

**Determinism is a security property.** The same inputs produce byte-identical outputs, verified by double-run hash comparison. Generated files carry no run timestamps. This means a reviewer can regenerate your package and confirm it matches what you shipped, which is a much stronger claim than trusting the file you sent.

**Automation reports, humans decide.** Collectors gather telemetry. Scanners report gaps. Neither may move a status to `Implemented`. A status changes when a deterministic check passes and a named human signs off. The planned generative layer drafts prose from collected facts and proposes a diff; it never approves its own work.

**Honest failure.** Running the readiness scanner against the shipped template produces thousands of findings. That is the correct output for an unfilled template, and the framework does not soften it, hide it behind a summary score, or let it block the build. A tool that reports green on an empty record is worse than no tool.

## Non-goals

Stating these plainly saves everyone time.

- **Not a compliance-as-a-service product.** No hosted dashboard, no scoring, no badge that says you are compliant.
- **Not an assessor replacement.** The framework makes an assessor's job faster by making evidence traceable. It does not perform assessment, and nothing in it constitutes an independent judgment.
- **Not a policy generator.** It will not write your incident response plan. It records what you actually do, points at the requirement that asks for it, and tells you when a claim has no evidence behind it.
- **Not multi-framework.** This targets FedRAMP 20x. The Revision 5 crosswalk exists to help providers migrating from a Revision 5 package, not to make this a general control-mapping tool.
- **Not a home for customer data.** Ever. See the [security policy](../SECURITY.md).

## Roadmap

Ordered by how much each unblocks a real provider, not by how interesting it is to build.

| Stage | What it delivers | State |
|---|---|---|
| Deterministic pipeline | Classes A, B, C generated, validated, byte-stable | Shipped |
| Readiness scanning | Per-rule and per-indicator findings citing the governing rule | Shipped |
| Continuous integration | GitHub Actions gate plus a deployable AWS CodePipeline reference | Shipped |
| Layer 1 collectors | Read-only evidence collection from a live AWS account | Shipped for AWS Config managed rules; more collectors needed |
| Layer 2 drafting | An Amazon Bedrock agent that drafts narratives from collected facts and proposes a reviewable diff | Planned |
| Infrastructure annotations | Link infrastructure-as-code resources to the indicators they satisfy | Planned |
| Class D | Full support once FedRAMP publishes the Class D path, currently listed for 2027 | Blocked on FedRAMP |

## Where this came from

FedRAMP 20x moved the program toward machine-readable, continuously validated evidence, and published the rules as a versioned dataset rather than a set of documents. That change makes a code-shaped approach possible for the first time. This repository is an attempt to take that seriously rather than wrapping the old document workflow in new vocabulary.

Related reading: [architecture](architecture.md) for how the pieces fit, [validation](validation.md) for what is actually checked.
