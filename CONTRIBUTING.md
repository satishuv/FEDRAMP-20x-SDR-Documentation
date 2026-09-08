# Contributing

Corrections to requirement interpretation are the most valuable contribution here, and they carry the highest bar.

## The one hard rule

**Cite the rule identifier and quote its statement from the dataset.** Not from memory, not from a blog post, not from a previous FedRAMP phase.

An interpretation argued without a citation will be asked for one. This is not gatekeeping. Requirement text changes between phases, identifiers changed shape when 20x arrived, and a plausible-sounding paraphrase in an authorization framework can send a provider down a path that costs them an assessment cycle.

How to check a claim before opening a pull request:

```python
import json
ds = json.load(open("references/fedramp-consolidated-rules.json", encoding="utf-8"))

# Rules nest five deep. Applicability is all, 20x, or rev5.
for family, fam in ds["FRR"].items():
    for applicability, group in (fam.get("data") or {}).items():
        for subset, rules in (group or {}).items():
            if isinstance(rules, dict) and "FRC-CSX-VVK" in rules:
                print(family, applicability, subset)
                print(rules["FRC-CSX-VVK"])
```

Reading only `data["all"]` will make every `*-CSX-*` rule look nonexistent. That mistake has been made by careful people, including automated reviewers, so verify your traversal before concluding an identifier is wrong. The [architecture page](docs/architecture.md#the-traversal-problem-and-why-it-is-called-out-everywhere) has the shape of all four dataset sections.

## What gets accepted quickly

- A rule identifier corrected, with the dataset path that proves it.
- A readiness check that catches a real gap, with the rule it enforces.
- A collector for a described-method entry that currently has no automation.
- Documentation that makes an actual first-time user faster. Bonus if you were that user and can say where you got stuck.
- A provider-specific map alongside the AWS one, so the framework stops looking AWS-only.

## What will be pushed back on

- Anything that lets a status reach `Implemented` without a deterministic check plus a named human. This is the trust boundary of the whole project.
- Generated content presented as evidence.
- Softening the readiness scanner so a template looks greener than it is.
- Widening the collector's permissions. It calls two APIs by design.
- Real customer data, in any form, including in a test fixture.
- Adding a dependency without a clear reason. Three is the current count and it is deliberate.

## Before you open a pull request

```bash
python sdr.py all
```

Confirm three things:

1. `hard failures: 0`.
2. `content_fidelity_against_dataset` passes, which proves you did not hand-edit a generated file.
3. If you changed `automation/sdrscan/checks.py`, regenerate the catalog: `python automation/sdrscan/sdrscan.py --write-catalog`. Continuous integration refuses a stale one.

Generated files do belong in commits, because the repository ships as a working template. What must not happen is a generated file that does not match what the pipeline produces from the same inputs. The regenerate-then-diff gate catches that.

## Commit messages

Describe the change and its reason. The existing history is a reasonable guide: `Pin every text writer and git blob to LF so CI regeneration is byte-stable` says what and why in one line.

No em dashes or en dashes anywhere in prose, including commit messages. Use a comma, colon, or a new sentence.

## Working with an AI assistant

Plenty of this repository was written with one, so this is not a purity test. Two things are required.

Point it at `.claude/rules/sdr-guardrails.md` and `CLAUDE.md` first. They encode the constraints that matter, including the traversal shape and the no-fabrication rule.

Verify every rule identifier it produces before it reaches a pull request. Assistants invent plausible identifiers, and they also confidently report correct identifiers as fabricated after indexing the dataset wrongly. Both failure modes have happened. The dataset is the arbiter, not the assistant and not the reviewer.

## Reporting a problem

Use the issue templates. The rule-question template exists specifically for "I think this interpretation is wrong," and it asks for the citation up front so the conversation starts in the right place.

Security and data-exposure problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

All rights in this repository are reserved by Amazon Web Services, Inc. and/or its affiliates (see [LICENSE](LICENSE)); this is not open-source software. By submitting a contribution you assign all rights in it to Amazon Web Services, Inc. and confirm you are authorized to do so. FedRAMP requirement text and schemas remain works of the United States government, published at [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules).
