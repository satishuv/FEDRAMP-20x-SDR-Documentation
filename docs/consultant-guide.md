# Consultant guide: using this framework for FedRAMP 20x work

Audience: an AWS security consultant (for example AWS Security Assurance Services)
helping a cloud service provider prepare a FedRAMP 20x Certification Package, for
greenfield or brownfield offerings, at Class A, B, or C.

This guide is deliberately in depth. It covers what the framework is, what it is
not, how the read-only collection works end to end, how many Key Security
Indicators are covered and how, the trust boundary, the opt-in surfaces, install
and use, the two adoption models, and a consultant FAQ.

Advisory boundary: this framework, and this guide, are advisory tooling. Nothing
here is a compliance determination. A FedRAMP certification decision belongs to an
accredited independent assessment service and the FedRAMP program, never to this
tool or to a consultant using it.

---

## 1. What this is, in one paragraph

You (or the provider) maintain two JSON input files describing the offering and its
security decisions. One command turns those, plus the pinned official FedRAMP
Consolidated Rules for 2026 (CR26) dataset, into a complete, schema-valid,
cryptographically fingerprinted Certification Package: the Security Decision Record
(SDR), the Certification Package Overview (CPO), an example Ongoing Certification
Report (OCR), a Secure Configuration Guide (SCG) scaffold, and event-driven
incident / significant-change / vulnerability artifacts. A set of independent
checkers then proves the package is well-formed, faithful to the rulebook,
internally consistent, and reproducible, and a submission-readiness preflight
reports exactly what still blocks handing it to an assessor.

It is a deterministic, rules-driven engineering framework, not a compliance engine.

---

## 2. What it can and cannot do

### It CAN
- Resolve, per certification class, exactly which FedRAMP rules and KSIs apply,
  straight from the pinned CR26 dataset (no rule text is typed by hand).
- Generate every FedRAMP-defined package artifact and validate each against its
  official FedRAMP JSON schema.
- Independently re-derive every generated statement from the dataset and fail the
  build on any mismatch (content fidelity), so a builder bug or a hand-edit is
  caught.
- Turn read-only AWS telemetry into schema-valid evidence entries with a
  tamper-evident content hash, without ever setting a status.
- Gate submission readiness at the field level, refusing bare `TBD`, unjustified
  `N/A`, placeholder evidence, stale or non-Recognized assessments, an incomplete
  Class A external-assessment material set, and more.
- Bind a human signoff to a cryptographic hash of the package AND its authoritative
  inputs, so any post-signoff change to inputs or outputs invalidates the signoff.
- Detect upstream FedRAMP dataset/schema drift daily and open a review.
- Produce a reproducible, byte-identical build so a reviewer can regenerate and
  verify what you delivered.

### It CANNOT (by design)
- Decide compliance, certification, authorization, or "readiness to certify."
  Those are the accredited assessor's and the program's calls.
- Set or infer an implementation status from telemetry. Collection tells you what
  is configured; a human decides the status and signs it.
- Author or approve a human review. The pipeline never writes an approval.
- Generate a Class D deliverable. Class D is FedRAMP-pending and modeled only as a
  planning register.
- Host the provider-owned artifacts it references (trust center, availability
  service, the completed SCG, the independent-assessment report). It models and
  preflight-gates them; the provider supplies them.
- Read secrets or write to your AWS account beyond the opt-in, read-only collector
  and the explicitly opt-in store provisioner.

A green build proves the package is well-formed and internally consistent. It does
NOT prove the offering is secure or compliant.

---

## 3. Architecture, end to end

### 3.1 The two provider-owned inputs
- `profiles/common/offering-profile.json` - offering identity, `certification_class`
  (A/B/C), the FedRAMP independent-assessment block, availability-reporting
  references, CPO required-information, the MOT initial-certification exception
  block, and the trust-center / SCG URIs.
- `sdr/records/records-store.json` - the security-decision facts: 168 rule (FRR)
  entries and 46 KSI entries, each with implementation, verification, validation,
  independent verification/validation, assessor responses, and evidence pointers.

Nothing else in the repository is hand-edited; the content-fidelity check enforces
this (edit a generated file and the next build fails).

### 3.2 The authoritative source, pinned
- `references/fedramp-consolidated-rules.json` - the CR26 dataset (rule text, force,
  class applicability, KSIs, definitions). Source of truth.
- `references/sources.lock.json` - SHA-256 lock of the dataset and the official
  schemas. Build step 1 (`validate_upstream.py`) refuses to build if the pinned
  dataset does not match the official rules schema or the lock hashes.

### 3.3 The build pipeline (19 steps)
`python sdr.py build` runs, in dependency order: upstream validation; rule and KSI
catalog extraction; per-rule notes; per-class profiles (plus the Class C overlay and
Class D register); the collector registry; the SDR (JSON, extensions companion,
plain text); the CPO; the example OCR; the SCG scaffold; the event artifacts; the
OSCAL export; the authoring Word file; the Rev 5 -> 20x crosswalk; the applicability
decision ledger; the unified assurance graph; the cryptographic release manifest;
cross-artifact consistency; the evidence-coverage and reviewer reports; and a
self-contained HTML assurance-graph view. A missing expected artifact is a hard
failure, so the release manifest can never attest to an incomplete package.

### 3.4 The two checkers, different jobs
- `validate_sdr.py` (the build gate) runs 14 aggregate checks - official-schema
  validation, dataset-version and pinned-schema guards, rule and KSI coverage,
  KSI required fields, per-class automated-method minimums (`FRC-CSX-VVK`),
  human-readable hygiene, a sensitive-pattern scan across the whole bundle, content
  fidelity against the dataset, CR26 semantic completeness, no stale NIST edition,
  evidence linkage for populated MUSTs, and source-lock consistency. Zero hard
  failures gates the build. `python sdr.py validate` runs this plus the full
  validation gate (package schemas, CPO semantics, assurance-graph traceability,
  the human review register, evidence integrity, cross-artifact consistency) and
  the offline test suite.
- `sdrscan.py` (the readiness scanner) runs 37 checks producing one finding per rule
  and per indicator, each citing the CR26 rule that makes it a requirement. It does
  not gate; it orders the fill-in work.

### 3.5 Submission-readiness preflight
`python sdr.py package-preflight` (and `application-preflight`, which adds the
Marketplace listing and application-form prerequisites) answers the stricter
question: is this ready to hand to an assessor? It is deliberately hard to fool.
It enforces field-level readiness; class-correct scope; structured CPO completeness
against CR26-enumerated items; the Class A approved-framework allowlist and
per-framework material checklist; Recognized-assessor identity for the initial
assessment and any freshening; availability survivability; the MOT window and its
initial-certification exception; and a manifest-bound human signoff. Missing or
stale evidence is a readiness finding, never an automatic compliance failure.

### 3.6 The trust boundary
```
official CR26 -> applicability -> provider facts -> required SDR fields
   -> evidence -> validation -> independent checks -> package manifest
   -> human signoff -> submission preflight
```
Each arrow is enforced. The signoff binds to a SHA-256 of the manifest, and the
manifest hashes both authoritative inputs, so tampering anywhere breaks the chain.

---

## 4. Read-only AWS collection, in detail

This is the part most relevant to a hands-on assessment.

### 4.1 Read-only by construction, and what enforces it
- Every AWS call the collectors make is a `describe` / `list` / `get`, enumerated
  in a single allowlist, `READ_ONLY_ACTIONS` in
  `automation/collectors/collectors.py` (currently 46 actions across Security Hub,
  Access Analyzer, Inspector, GuardDuty, Backup, KMS, Config, CloudTrail, S3, IAM,
  CloudFormation, WAF, EC2, ECR, DynamoDB, EventBridge, CodePipeline, plus
  `sts:GetCallerIdentity`).
- The allowlist documents intent. The binding enforcement is the IAM role: the
  deployed `CollectorRole` (in `automation/pipeline/sdr-pipeline.yaml`) grants
  exactly that read-only action set and nothing that can mutate. A test
  (`test_collector_iam_matches.py`) asserts the granted actions are a superset of
  what the collectors call, so a new collector cannot ship without a matching grant.
- Run the collector with a ReadOnly or least-privilege profile, never admin.

### 4.2 What a collector produces
A collector emits FACTS, never statuses. A fact records `service`, `check`,
`status` (for example `ENABLED`, `NOT_ENABLED`, `PRESENT`, `OBSERVED`, or
`ERROR:<code>`), a short human `detail`, the `region`, and a `collected_at`
timestamp. Collection failure is explicitly not control failure: an `AccessDenied`,
throttling, or service error is recorded as an error/instrumentation fact and, in
the deployable Config custom rule, maps to `NOT_APPLICABLE` with an error
annotation - never to a negative control conclusion.

### 4.3 From fact to evidence
`evidence_wiring.py` turns a fact into a schema-valid `ksiEvidence[]` entry
(populating the official `evidenceType` / `evidenceDescription` /
`evidenceLocation` / `evidenceText` fields). It attaches a tamper-evident content
hash computed over a SANITIZED projection of the fact (an allowlist of non-sensitive
fields), and it persists that same sanitized projection as `xSourceFact` so a
reviewer or CI can recompute and verify the digest without over-exposing
environment detail. When it cannot know the durable artifact URI, it emits an
obvious `sdr://placeholder/` marker for a human to replace - and a placeholder
evidence URI in an applicable record BLOCKS submission preflight.

### 4.4 KSI coverage: how many, and how
There are 46 KSIs in 10 families (CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SCR,
SVC). Coverage of those 46 by direct AWS collection today:
- 35 of 46 have at least one directly collectable read-only check (a live AWS API
  exposes the state). The collector registry records 83 collectable checks across
  those, 137 checks total.
- The remaining 11 are governance/document/reviewed-process indicators whose
  evidence is a document or a reviewed-within-interval process, not a plain API
  field. Those are covered by a provider-deployed AWS Config custom rule
  (`automation/config-rules/`, deployable via generated CloudFormation or CDK) that
  checks the existence and freshness of a provider-supplied evidence object - again,
  telemetry, never a determination.

Coverage is telemetry that helps a human decide and evidence a status; it is never
itself a status.

### 4.5 Metric history (SDR-CSX-KMT) and the metric-of-time clock (FRC-CSX-MOT)
The scheduled collector pipeline runs daily. Each run restores the prior
`metric-history.json` from the evidence bucket, appends one dated datapoint per KSI,
and persists the updated history back, so the longitudinal history accumulates
across ephemeral runs. This is what feeds the Class C six-month persistent-validation
window; that window is a calendar dependency you cannot compress later, so start the
clock early.

---

## 5. Certification classes (what changes)

| | Class A | Class B | Class C |
|---|---|---|---|
| Provider rules resolved | 41 | 158 | 158 + overlay |
| KSIs in scope | 7 enumerated | 46 | 46 |
| Automated methods per KSI (`FRC-CSX-VVK`) | 0 required | >= 1 (SHOULD) | >= 2 (MUST) |
| Persistent validation history (`FRC-CSX-MOT`) | MAY | SHOULD | MUST >= 6 months |
| Independent assessment | Alternative framework (SOC 2 Type II, FedRAMP Rev5/Ready, or GovRAMP) within 12 months | FedRAMP Recognized within 3 months (freshenable to 9) | same as B |

Class A is enumerated, not a scaled-down B: its 41 rules and 7 KSIs are the ones
FedRAMP named (`FRC-CLA-MFR`), and its CPO carries only the applicable subset of the
overview rules. Class D is a planning register only, not a generatable deliverable.

Switch class with one field (`certification_class`) in the offering profile, then
rebuild.

---

## 6. Opt-in surfaces (nothing below runs unless you choose it)

The core generator is local and offline. Everything that touches AWS or third
parties is opt-in:
- AWS read-only collectors (`collect_facts.py`) - you point them at an account with a
  ReadOnly profile.
- The scheduled collector pipeline (`automation/pipeline/`) - a CodeBuild project and
  daily schedule, deployed only when `EnableCollectorSchedule=true`.
- The provider-deployed Config custom rules (`automation/config-rules/`) - deployed
  via generated CloudFormation or CDK for the 11 document/process indicators.
- The durable store provisioner (`automation/storage/provision_store.py`) - creates a
  versioned (optionally Object Lock) evidence bucket; safety-additive, and it merges
  rather than replaces existing S3 lifecycle rules.
- Opt-in AI assist (`automation/ai/`) - five modules with a deterministic offline
  default and an optional Amazon Bedrock backend, boundary-guarded so AI can never
  set a status.
- Third-party evidence adapters (CrowdStrike Falcon, Wiz).
- The OSCAL export and the shift-left policy-as-code example are reference/interop
  outputs; treat them as experimental for a customer bundle until schema-validated
  for your consuming tool.

---

## 7. Install and use

### Prerequisites
Python 3.10 or later, and the pinned dependencies:
```bash
python -m pip install -r requirements.txt
```

### First run (local, no AWS, no network)
```bash
git clone https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation.git
cd FEDRAMP-20x-SDR-Documentation
python sdr.py all          # build + validate + scan + summary
```
Expect `hard failures: 0` on a fresh clone, with two advisory Class B failures
(`ksi_test_minimums`, `evidence_linkage_for_populated_musts`) that are `SHOULD`-force
at Class B, and many open readiness findings - the repo ships as a template.

### The commands you will use
- `python sdr.py explain <RULE-ID|KSI-ID>` - the requirement text, force, class
  applicability (verbatim from the dataset) plus the record's current status.
- `python automation/sdrscan/sdrscan.py --only-fails --severity critical,high` - the
  ordered work queue.
- `python sdr.py build` - regenerate after editing the inputs.
- `python sdr.py package-preflight` / `application-preflight` - what still blocks
  submission.
- `python sdr.py release` - build + full gate + reproducibility double-build + tag.

### The loop
Edit `records-store.json` (and the offering profile), rebuild, read the scanner and
preflight, fix the next gap, repeat. Never edit a generated file.

---

## 8. Using it on a real assessment: greenfield and brownfield

FedRAMP obligations are set by certification class, not by system age; greenfield vs
brownfield is a practical lens, not a FedRAMP distinction. Either way the pipeline,
gates, drift check, and trust boundary are identical, and neither path shortcuts
human verification or the independent assessment.

### Greenfield (new offering built for 20x)
- Adopt the framework at the start so the record grows with the system and each KSI
  narrative is written as the capability is built.
- Stand up the durable store and the daily collector early: the metric-of-time
  history cannot be backfilled, and Class C needs six months.
- Expect many honest `Not Implemented` and not-enabled results early - that is
  correct for a system still being built.

### Brownfield (existing offering adopting 20x - often the common case)
- Point the read-only collectors at the existing account and let prefill map the
  collected facts into a populated starting draft rather than a blank template.
- Expect a remediation pass: the collectors surface real drift honestly.
- The metric history still starts accumulating only at adoption, and the
  document/process indicators still need the provider to wire up the evidence
  location the Config custom rules check.

### A consultant workflow that works
1. Choose the class with the provider (mind the Class C calendar dependencies).
2. Fill the offering profile identity and the assessment / availability / CPO inputs.
3. For brownfield, run the read-only collectors and prefill; for greenfield, start
   the store and daily collector.
4. Work the scanner's critical/high findings, writing real implementation and
   verification narratives and attaching real evidence locations.
5. Run `package-preflight` and clear every blocker.
6. Have the accountable human review and sign the package (the signoff binds to the
   manifest hash).
7. Deliver the reproducible package; the assessor regenerates and verifies it.

You provide advisory guidance and engineering help. You do not make the compliance
determination, and you should not let a green build or a "ready" preflight be read
as one.

---

## 9. FAQ

**Is a green build a pass / compliant / certified?**
No. Green means well-formed, schema-valid, internally consistent, traceable, and
reproducible. Certification is the accredited assessor's and the program's decision.

**Does it change anything in my AWS account?**
The core generator does not touch AWS at all. The opt-in collectors are strictly
read-only (allowlist + IAM role). The only write paths are opt-in and explicit: the
store provisioner (safety-additive, preserves existing lifecycle rules) and writing
collected facts/history to the evidence bucket.

**How does it guarantee the collectors are read-only?**
Two layers: an action allowlist in code, and the deployed IAM role that grants only
that read-only set (a test enforces role ⊇ collector calls). The IAM role is the
real enforcement in the deployed path.

**How many KSIs does automated collection cover?**
35 of 46 have at least one direct read-only check now; the other 11 are
document/process indicators covered by a provider-deployed Config custom rule that
checks evidence existence and freshness. All 46 are modeled and scanned.

**Can automated collection set a KSI to Implemented?**
No. Collection produces telemetry. A human moves a status to Implemented only when a
deterministic check passes and a named person signs off; AI assist is advisory and
boundary-guarded from statuses.

**What about Class D?**
Not an active path. It is a planning register (`profiles/class-d-future/`); the
framework will not generate a Class D deliverable.

**Can I trust the "submission ready" result?**
Preflight is designed to be hard to fool: field-level, class-correct, structured CPO
checks, Recognized-assessor identity, MOT, and manifest-bound signoff, all grounded
verbatim in CR26, with adversarial tests. It reports readiness; it still is not a
compliance determination.

**Is the data I collect sent anywhere?**
No. Collection writes to the provider's own evidence bucket in the provider's own
account. Evidence persisted into the package is a sanitized, allowlisted projection,
not the raw fact.

**What are the licensing / distribution terms?**
Licensing is owned by the AWS SAS team and is being confirmed with AWS legal. Confirm
the current LICENSE and your distribution authorization before handing the repository
to a customer.

---

## 10. Where to go deeper
- Architecture: [architecture.md](architecture.md)
- Validation, the gate, and preflight: [validation.md](validation.md)
- Certification classes: [certification-classes.md](certification-classes.md)
- Automation layers and the collectors: [automation.md](automation.md)
- Getting started: [getting-started.md](getting-started.md)
- Implementation guide (per-field): [implementation-guide.md](implementation-guide.md)
- Deployment and CI: [deployment.md](deployment.md), [ci-cd.md](ci-cd.md)
- Scanner reference: [../automation/sdrscan/README.md](../automation/sdrscan/README.md)

This guide is documentation, not a compliance determination or professional advice.
Regulatory interpretation requires qualified counsel; a FedRAMP certification
decision belongs to an accredited independent assessment service and the FedRAMP
program.
