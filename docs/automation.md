# Automation layers

The framework separates automation into layers by what each is allowed to decide. This is the boundary that keeps generated content out of the evidence chain.

| Layer | What it does | May it move a status? |
|---|---|---|
| Layer 0: the pipeline | Resolves requirement text, generates deliverables, validates | No. It records what you wrote |
| Layer 1: collectors | Read-only queries against a live account, producing timestamped facts | No. Facts are telemetry |
| Layer 2: drafting, planned | Drafts narrative prose from collected facts, proposes a reviewable diff | No. It proposes; a human approves |

The rule underneath all three: a status moves to `Implemented` when a deterministic check passes and a named human signs off. Nothing else qualifies. Generative output is never deterministic telemetry, which follows from FedRAMP's own definitions of verification and validation, so a drafted sentence can never be the evidence for the claim it makes.

## Layer 1: the facts collector

`traceability/aws-service-ksi-map.json` links every indicator to example Amazon Web Services implementation guidance, with one verify method and one validate method each, matching the two-method shape `FRC-CSX-VVK` asks for.

From that map, `build_collector_registry.py` derives `automation/collectors/registry.json`: all 46 indicators, with any AWS Config managed rule named in the guidance extracted as an immediately collectable check, and the prose methods carried as described-method entries until a dedicated collector implements them.

`automation/collectors/collect_facts.py` runs the collectable checks against an account and writes a timestamped facts store to `automation/facts/`.

### Read-only by construction

The collector is constrained by design rather than by policy documentation:

- It calls exactly two APIs: `config:DescribeComplianceByConfigRule` and `sts:GetCallerIdentity`. Nothing else.
- It refuses to run under credentials that look administrative.
- `automation/facts/` is git-excluded, because a facts store identifies a real account.

Grant it a role with those two permissions and nothing more. If it needs anything else later, that is a change worth reviewing rather than a permission worth widening pre-emptively.

```bash
python automation/collectors/collect_facts.py
```

### What to do with the output

Facts feed three things: the automated methods you cite in an indicator's `tests`, the evidence pointers in `evidence`, and the metric history that `SDR-CSX-KMT` requires at Class C, where all daily metric data must be retained up to a year.

Facts do not write into the record store. You read them, decide what they demonstrate, and write that. The gap between "the collector saw a passing Config rule" and "this indicator is implemented" is a judgment, and the framework insists a person makes it.

## Layer 2: drafting, planned

An Amazon Bedrock drafter and an interview agent, with hard constraints already fixed:

- Drafts prose only from facts already collected. No invented specifics, no plausible-sounding detail that no telemetry supports.
- Produces a diff against the record store for human review. It does not write the store.
- Cannot set a status. Ever.
- Cannot produce evidence. A drafted sentence is a description of evidence, never the evidence.

Why bother at all: the bottleneck in a real record is not knowing what the controls are, it is writing 214 entries of clear prose describing them. A drafter that turns collected facts into a first draft, which a person then corrects, addresses the actual cost without touching the trust boundary.

Also planned: annotating infrastructure-as-code modules with the indicators they satisfy, so the link between a resource and a requirement lives next to the resource.

## What deliberately is not automated

**Status transitions.** The whole point.

**Assessment conclusions.** The `assessment` field stays `TBD` until an accredited independent assessor has actually assessed. No tool in this repository writes it.

**Deviation justifications.** If you take an exception, a person writes why and a named senior official accepts the residual risk. A generated justification is worthless in the meeting where it matters.

**Anything requiring write access to your account.** The collector is read-only and stays that way.

See [validation](validation.md) for how collected facts flow into the checks, and the [implementation guide](implementation-guide.md) for how to turn a fact into a defensible entry.
