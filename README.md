<h1 align="center">FedRAMP 20x Certification Package Framework</h1>

<p align="center">
  <strong>Build and maintain your FedRAMP 20x Certification Package from traceable, machine-readable facts, not hand-maintained documents.</strong><br>
  One file of facts becomes a schema-validated Security Decision Record, Certification Package Overview, Ongoing Certification Report, Secure Configuration Guide, and the event-driven artifacts, every JSON validated against its official FedRAMP schema.
</p>

<p align="center">
  <a href="https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation/actions/workflows/validate.yml"><img alt="Validate" src="https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation/actions/workflows/validate.yml/badge.svg"></a>
  <a href="https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation/actions/workflows/drift-check.yml"><img alt="Upstream drift" src="https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation/actions/workflows/drift-check.yml/badge.svg"></a>
  <img alt="CR26 dataset" src="https://img.shields.io/badge/CR26%20dataset-2026.07.14.01-0b7285">
  <img alt="Classes" src="https://img.shields.io/badge/classes-A%20%7C%20B%20%7C%20C-1864ab">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776ab">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-All%20Rights%20Reserved-c92a2a"></a>
</p>

<p align="center">
  <a href="docs/getting-started.md">Get started</a> &middot;
  <a href="docs/implementation-guide.md">Fill in your facts</a> &middot;
  <a href="docs/architecture.md">Architecture</a> &middot;
  <a href="docs/vision.md">Vision</a> &middot;
  <a href="docs/glossary.md">Glossary</a>
</p>

<p align="center">
  <sub>Pinned to CR26 dataset <code>2026.07.14.01</code>. A scheduled <a href="https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation/actions/workflows/drift-check.yml">drift check</a> hash-compares the pinned dataset and schemas against <a href="https://github.com/FedRAMP/rules">github.com/FedRAMP/rules</a> daily and opens an issue on any change. Green drift badge above means the pin still matches upstream.</sub>
</p>

---

> [!CAUTION]
> ## Read this before you use anything this repository produces
>
> **This is not a compliance audit bot. It does not generate compliance.**
>
> This framework is an authoring and formatting aid. It assembles a schema-valid document and scaffolds draft text. It does **not** assess, certify, or attest anything, and it **cannot** make you FedRAMP 20x compliant.
>
> - **Nothing generated here is compliant, verified, or authoritative.** Any Security Decision Record (SDR), Key Security Indicator (KSI) narrative, implementation text, validation text, evidence summary, finding explanation, or any other output — whether produced by the deterministic pipeline or by an optional AI-assist module — is an **unverified draft only**. It carries no assurance of accuracy, completeness, or correctness.
>
> - **Producing a document with this repository does not guarantee, imply, or contribute to FedRAMP 20x compliance.** Passing the build gate means the file is *well-formed*, not that the *claims in it are true*. A green build is a formatting check, never a compliance determination.
>
> - **Every single letter must be independently re-checked and verified by a qualified human before any use.** Do not submit, rely on, or represent any output of this repository as fact, as evidence, or as a compliance position until a knowledgeable person has read it end to end, confirmed every statement against the actual system and the authoritative FedRAMP sources, and taken ownership of it. Treat all generated text as a starting draft to be rewritten, not as an answer.
>
> - **AI-assisted output is especially not to be trusted as-is.** The optional AI modules draft, explain, summarize, flag, and suggest. They can be wrong, incomplete, or misleading, and they may state things the underlying facts do not support. They never gather evidence, never set an implementation status, and never write an assessment — those remain human decisions with human sign-off. AI output is a suggestion for a human to verify, nothing more.
>
> - **Compliance is determined only by an accredited independent assessor and the authorizing body — never by this tool.** No software, and nothing in this repository, can grant, promise, or substitute for a real FedRAMP 20x authorization.
>
> - **No warranty. Use entirely at your own risk.** This software is provided "as is," without warranty of any kind. The authors and rights holders accept no liability for any use, misuse, or reliance on it or on anything it produces.
>
> **Ownership and rights.** This work is associated with and developed in the context of **Amazon Web Services (AWS) Security Assurance Services (SAS)**. AWS Security Assurance Services and its affiliates reserve all rights in and to this work to the fullest extent applicable. All AWS-related names, marks, and materials remain the property of Amazon Web Services, Inc. and its affiliates. Use of this repository does not transfer any such rights, and nothing here should be read as an official AWS position, product, or service. FedRAMP requirement text and schemas remain the property of their respective owners (see [License and rights](#license-and-rights)).

---

## The problem

FedRAMP 20x asks providers for a machine-readable, schema-valid Certification Package, not a stack of Word documents. At its center is the Security Decision Record (SDR), backed by automated verification: `FRC-CSX-VVK` calls for automated methods to persistently verify and validate each Key Security Indicator, with the obligation rising by class (`MAY` at A, `SHOULD` at B, `MUST` at C and D), and `FRC-CSX-VVR` asks for the same across the SDR itself. The initial package (`FRC-CSO-PKG`) also requires a Certification Package Overview, a real or example Ongoing Certification Report, and, for Class B/C, a Secure Configuration Guide.

A hand-maintained document set cannot satisfy that. It drifts from the requirement text the moment FedRAMP updates the dataset, it cannot be diffed, and it gives an assessor no way to trace a sentence back to the rule that demanded it.

## The approach

In plain terms: you write facts about your system, and the framework turns them into an official, self-checking Certification Package. You maintain one file; everything else is generated and verified for you.

<p align="center">
  <img src="docs/assets/architecture.svg" alt="How it works: your system's facts (records-store.json, the one file you edit) and the official rulebook (the pinned FedRAMP CR26 dataset and JSON schemas) feed the builder (python sdr.py all), which produces the full Certification Package (Security Decision Record, Certification Package Overview, Ongoing Certification Report, Secure Configuration Guide, and the event-driven incident, change, and vulnerability artifacts), every JSON validated against its official FedRAMP schema. Optional evidence sources (AWS collectors, and opt-in CrowdStrike Falcon and Wiz) attach hashed evidence. Two automatic checkers inspect the output: the fact-checker (validate_sdr.py plus validate_package.py) fails the build if a claim does not match the rulebook or a document does not match its schema, and the readiness scanner (sdrscan.py) scores how ready you are. Together they form a loop that points you back to what to fix next in your facts file. A daily drift check compares the pinned sources against upstream FedRAMP." width="820">
</p>

Two inputs, one pipeline, several official-schema artifacts, two checkers with different jobs, and a loop that tells you what to write next.

Requirement text is never typed by hand. It is resolved from the canonical FedRAMP Consolidated Rules for 2026 (CR26) dataset, and an independent validator re-derives every statement from that dataset and fails the build on any mismatch. Every generated JSON artifact is validated against its official FedRAMP schema. You write facts about your system. The framework writes everything else.

## Quickstart

```bash
git clone https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation.git
cd FEDRAMP-20x-SDR-Documentation
pip install jsonschema referencing python-docx

python sdr.py all
```

That builds every deliverable, runs the validator, and prints a readiness summary. Expect `hard failures: 0` and a long list of open items: the repository ships as a template with honest placeholders, so open items are the correct result on a fresh clone.

Then open `sdr/records/records-store.json` and start replacing `TBD` with facts about your system. That file is the only one you edit. See the [implementation guide](docs/implementation-guide.md).

If you have GNU make, `make all` wraps the same command. To run the build steps individually, see [getting started](docs/getting-started.md).

## What you get

Every JSON artifact below is validated against its official FedRAMP schema; the whole set is regenerated by one command.

| Deliverable | Path | Purpose |
|---|---|---|
| Security Decision Record (JSON) | `sdr/json/sdr-class-*.json` | The core record. Validates against the official SDR schema; required semantic items carried in `providerExtensions.xFedRampSemantic` |
| SDR plain text and Word | `sdr/human-readable/sdr-class-*.txt` / `*-authoring.docx` | Human-readable halves; `.txt` keeps parity with the JSON per `CDS-CSO-CBF` |
| Certification Package Overview | `package/cpo/cpo.json` / `.md` | `CPO-CSO-OVR`. Validates against the official CPO schema |
| Ongoing Certification Report (example) | `package/ocr/ocr-example.json` / `.md` | `CCM-OCR-AVL`. Validates against the official OCR schema |
| Secure Configuration Guide | `package/scg/secure-configuration-guide.md` | `SCG-CSO-RSC` / `SCG-CSO-AUP` scaffold (no JSON schema exists for the SCG) |
| Event artifacts (examples) | `package/events/*.json` | Incident Report, Significant Change Notification, and the vulnerability set (VDR/VER), each schema-validated |
| Rev5 related-control index | `traceability/rev5-to-20x-crosswalk.csv` | NIST SP 800-53 Rev. 5 (Release 5.2.0) controls related to each 20x indicator |
| OSCAL export | `sdr/json/sdr-class-*.oscal.json` | Interoperability only; not a native 20x submission format |
| Validation report | `validation/reports/validation-report.json` | 13 checks, one exit code, gates the build |
| Readiness findings | `validation/reports/sdrscan/` | One finding per rule and per indicator, severity-ranked |

## Deploy it

You do not deploy this framework to run it: it is a local, offline generator. `python sdr.py all` produces every artifact on your machine with no cloud account and no network. Where "deployment" matters is publishing the finished package and wiring continuous verification. Three paths, smallest first:

1. Local only. Clone, `pip install jsonschema referencing python-docx`, run `python sdr.py all`. This is the whole tool. Everything else is optional.
2. Continuous integration. The included GitHub Actions `validate.yml` runs the build gate on every push and pull request; `drift-check.yml` hash-compares the pinned FedRAMP sources against upstream daily and opens an issue on any change. Fork, and both run for free with no secrets. Security scanning (ASH and Fortify) runs as a local pre-commit gate, not in CI: install it once per clone with `scripts/install-fortify-hook.ps1`.
3. Provider pipeline in your own AWS account. `automation/pipeline/` holds a deployable AWS CodePipeline reference (regenerate, validate, human-approval gate, publish to a versioned encrypted S3 bucket that can back a trust center). See [continuous integration](docs/ci-cd.md) and [the deployment guide](docs/deployment.md).

Per-customer work belongs in a private fork: copy this repository, edit only `profiles/common/offering-profile.json` and `sdr/records/records-store.json`, and never commit customer values to the public template.

## Opt in to optional features

The core is deterministic and offline. Everything below is off by default and enabled deliberately.

| Feature | How to turn it on | What it adds |
|---|---|---|
| AWS evidence collectors | Run `automation/collectors/collect_facts.py` with read-only AWS credentials | Collects posture telemetry into evidence, no status set |
| CrowdStrike Falcon evidence | Set `evidence_sources.crowdstrike-falcon.enabled: true` in the offering profile, point `export_path` at a Falcon export, run `automation/collectors/apply_third_party_evidence.py` | Attaches endpoint-detection evidence to `KSI-MLA-OSM/RVL/LET`, `KSI-INR-RIR` |
| Wiz evidence | Set `evidence_sources.wiz.enabled: true`, point `export_path` at a Wiz export, run the same driver | Attaches posture and vulnerability evidence to `KSI-MLA-EVC/OSM`, `KSI-SCR-MON` |
| AI-assist drafting | Opt-in modules under `automation/ai/` | Drafts and explains text for a human to verify; never sets a status |
| Explain a requirement | `python sdr.py explain FRC-CSO-PKG` or `KSI-CNA-RNT` | Plain-language, dataset-grounded summary of one rule or KSI |

Both third-party evidence sources read a file the customer exports in their own environment. This repository holds no Falcon or Wiz API client and no credentials, so a customer who uses neither tool sees nothing change. See [optional evidence sources](examples/evidence-sources/README.md).

## Scope today

| Class | Rules resolved | Indicators | Automated methods per indicator | State |
|---|---|---|---|---|
| A | 41 | 7 mandatory | 0 required | Supported |
| B | 158 | 46 | at least 1 | Supported |
| C | 158 plus overlay | 46 | at least 2 | Supported |
| D | 157 | 46 | at least 4 | Readiness register only. FedRAMP 20x Class D (High) is in Phase 4 development ([RFC-0033](https://www.fedramp.gov/rfcs/0033/)), pilot estimated FY27 Q1-Q2 |

`FRD-CCL` describes the classes as assurance categories "increasing from minimal assurance at Class A to significant assurance at Class D." FedRAMP's current 20x guidance maps them to impact levels: Class A (Pilot), Class B (Low), Class C (Moderate), and the planned Class D (High), per the [FedRAMP 20x page](https://www.fedramp.gov/20x/). Those labels do not make the 20x indicator profile a renamed NIST SP 800-53B baseline, so this framework tracks the class but does not infer baseline equivalence.

Derived from the CR26 dataset at version `2026.07.14.01`: 234 rules in 20x scope out of 246 total entries, the remaining 12 being rev5-only, plus 46 Key Security Indicators across 10 families.

## What this is not

Being direct about this matters more than adoption numbers. See the [caution banner](#read-this-before-you-use-anything-this-repository-produces) at the top for the full statement; in short:

- Not a compliance claim, and not a compliance generator. Every status ships as `Not Implemented` or `TBD`. Nothing here asserts that anyone meets a requirement, and no output of the pipeline or the AI modules is compliant or verified.
- Not a shortcut past assessment. It produces a defensible draft record; an accredited independent assessor still does the assessing. A green build is a formatting check, not a compliance determination.
- Not trustworthy without human verification. Every generated statement — deterministic or AI-assisted — is an unverified draft. Every letter must be re-checked and confirmed by a qualified human before any use.
- Not a place for customer data. No account identifiers, credentials, endpoints, or restricted report content, ever. Per-customer work belongs in a separate private repository. The validator actively scans for leaked secrets and fails on a hit.
- Not affiliated with or endorsed by FedRAMP. FedRAMP publishes the rules; this repository consumes them. Nothing here is an official AWS position, product, or service.

## Documentation

| Guide | Read it when |
|---|---|
| [Getting started](docs/getting-started.md) | You want a validated SDR on your machine in five minutes |
| [Implementation guide](docs/implementation-guide.md) | You are filling in your own facts and need to know what each field wants |
| [Architecture](docs/architecture.md) | You want to know why the pipeline is shaped this way |
| [Certification classes](docs/certification-classes.md) | You are deciding between Class A, B, C, or planning for D |
| [Validation and readiness](docs/validation.md) | You want to understand the build gate and the readiness scanner |
| [Continuous integration](docs/ci-cd.md) | You are wiring this into GitHub Actions or AWS CodePipeline |
| [Deployment](docs/deployment.md) | You want to publish the package and stand up continuous verification |
| [Optional evidence sources](examples/evidence-sources/README.md) | You run CrowdStrike Falcon or Wiz and want that telemetry as evidence |
| [How this relates to official FedRAMP repos](docs/comparison.md) | You want the capability comparison against FedRAMP/rules, /2026, and /2026-markdown |
| [Automation layers](docs/automation.md) | You want evidence collected from a live account rather than typed |
| [Glossary](docs/glossary.md) | An acronym is in your way |
| [Frequently asked questions](docs/faq.md) | Something surprised you |
| [Vision and mission](docs/vision.md) | You want to know where this is going and what it refuses to do |

## Contributing

Corrections to requirement interpretation are the most valuable contributions, and they are held to a hard standard: cite the rule identifier and quote its statement from the dataset. See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md), not public issues.

## License and rights

All rights reserved. See [LICENSE](LICENSE). This is not open-source software; no license or permission to use, copy, modify, or distribute is granted without prior express written permission of Amazon Web Services, Inc.

This work is associated with **Amazon Web Services (AWS) Security Assurance Services (SAS)**. AWS Security Assurance Services and its affiliates reserve all rights in and to this work to the fullest extent applicable, and all AWS names, marks, and materials remain the property of Amazon Web Services, Inc. and its affiliates. Nothing here is an official AWS position, product, service, or endorsement.

FedRAMP requirement text and schemas are published by the United States General Services Administration at [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules) and are reproduced here under their terms as government works.

