# Automation layers

The framework separates automation into layers by what each is allowed to decide. This is the boundary that keeps generated content out of the evidence chain.

| Layer | What it does | May it move a status? |
|---|---|---|
| Layer 0: the pipeline | Resolves requirement text, generates deliverables, validates | No. It records what you wrote |
| Layer 1: collectors | Read-only queries against a live account, producing timestamped facts | No. Facts are telemetry |
| Layer 2: AI assist (opt-in) | Drafts narrative prose, explains findings, summarizes, flags over-claims, suggests mappings | No. It proposes; a human approves |

The rule underneath all three: a status moves to `Implemented` when a deterministic check passes and a named human signs off. Nothing else qualifies. Generative output is never deterministic telemetry, which follows from FedRAMP's own definitions of verification and validation, so a drafted sentence can never be the evidence for the claim it makes.

## Layer 1: the facts collector

`traceability/aws-service-ksi-map.json` links every indicator to example Amazon Web Services implementation guidance, with one verify method and one validate method each, matching the two-method shape `FRC-CSX-VVK` asks for.

From that map, `build_collector_registry.py` derives `automation/collectors/registry.json`: all 46 indicators, with any AWS Config managed rule named in the guidance extracted as an immediately collectable check, and each described method wired to a read-only collector where a live API exposes the state. Today 35 of the 46 indicators have at least one directly collectable read-only check; the remaining 11, whose evidence is a document or a reviewed process, are covered by provider-deployed AWS Config custom rules (see `automation/config-rules/`). The registry regenerates this classification deterministically from `automation/collectors/pending-ksi-classification.json`.

`automation/collectors/collect_facts.py` runs the collectable checks against an account and writes a timestamped facts store to `automation/facts/`. `collect_multi_account.py` fans the same read-only collection across accounts.

### Read-only by construction

The collector is constrained by design rather than by policy documentation:

- Every AWS action it may call is enumerated in a read-only allowlist (`READ_ONLY_ACTIONS` in `collectors.py`); the driver refuses any call not in that set, and a test asserts every entry is a read verb (Get, List, Describe, BatchGet). Adding a service means adding its read-only actions to that set on purpose, a reviewable change rather than a silent permission widening.
- It refuses to run under credentials that look administrative.
- `automation/facts/` is git-excluded, because a facts store identifies a real account.

Grant it a role scoped to exactly the read-only actions in the allowlist and nothing more. If a new collector needs an action later, that is a change worth reviewing rather than a permission worth widening pre-emptively.

```bash
python automation/collectors/collect_facts.py
```

### What to do with the output

Facts feed three things: the automated methods you cite in an indicator's `tests`, the evidence pointers in `evidence`, and the metric history that `SDR-CSX-KMT` requires at Class C, where all daily metric data must be retained up to a year.

Facts do not write into the record store. You read them, decide what they demonstrate, and write that. The gap between "the collector saw a passing Config rule" and "this indicator is implemented" is a judgment, and the framework insists a person makes it.

## Layer 2: AI assist (opt-in, built)

Five optional AI-assist modules live in `automation/ai/`, each a separate pluggable component with hard constraints fixed in code:

- `draft_narratives.py` drafts implementation and validation prose into to-be-determined fields only; a per-indicator guard blocks any change to a forbidden field (status, assessment, tests, evidence) and writes only to a git-ignored draft sidecar.
- `explain_findings.py` explains findings in plain English. Advisory, no write path.
- `rollup_evidence.py` summarizes dated facts into a paragraph. Summarizes only, never claims.
- `review_overclaim.py` flags draft prose that claims more than the facts support. Flags only, never edits.
- `suggest_ksi_mapping.py` suggests which indicators a provider's services support. Suggestions only, confirmed by a human against the dataset.

Shared constraints, proven by 27 offline boundary tests wired into CI:

- Drafts, explains, summarizes, flags, or suggests only from facts already collected. No invented specifics.
- Produces a diff or advisory output for human review. It never writes the record store.
- Cannot set a status. Ever. Cannot produce evidence.
- Default backend is offline and deterministic (no model, no network); an Amazon Bedrock backend is opt-in per module and imports its client only when explicitly chosen. The provider decides the backend and whether any data leaves their boundary.

Why bother at all: the bottleneck in a real record is not knowing what the controls are, it is writing the narrative entries of clear prose describing them. A drafter that turns collected facts into a first draft, which a person then corrects, addresses the actual cost without touching the trust boundary.

Also planned: annotating infrastructure-as-code modules with the indicators they satisfy, so the link between a resource and a requirement lives next to the resource.

## What deliberately is not automated

**Status transitions.** The whole point.

**Assessment conclusions.** The `assessment` field stays `TBD` until an accredited independent assessor has actually assessed. No tool in this repository writes it.

**Deviation justifications.** If you take an exception, a person writes why and a named senior official accepts the residual risk. A generated justification is worthless in the meeting where it matters.

**Anything requiring write access to your account.** The collector is read-only and stays that way.

See [validation](validation.md) for how collected facts flow into the checks, and the [implementation guide](implementation-guide.md) for how to turn a fact into a defensible entry.
