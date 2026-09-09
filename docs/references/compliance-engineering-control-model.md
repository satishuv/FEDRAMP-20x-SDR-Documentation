# Reference: AWS compliance-engineering control model

A distilled reference from a walkthrough by Sean McMahon, cloud infrastructure
architect in compliance engineering at AWS Security Assurance Services, on how
AWS builds and layers compliance controls. Captured here because it frames where
this SDR framework sits relative to the broader control stack.

This is a distilled note, not a transcript, and it is reference material — not a
FedRAMP requirement and not an instruction to change the framework.

## The control layers described

- **Continuous evidence collection.** Attestation is moving from point-in-time
  spreadsheets to continuous compliance via self-monitoring; evidence is fed
  into a trust center, sometimes in a specific format such as OSCAL. Custom
  collectors convert or capture what the built-ins miss.
- **Policy monitoring dashboards.** Security Hub (with standards such as NIST
  800-53) or a custom QuickSight build. A favorite is a dashboard that proves
  control **efficacy** — showing that deployed SCPs, OPA rules, and Guard rules
  are actually matching, so a rule that matches nothing can be investigated.
- **Detective controls.** Custom AWS Config rules (and conformance packs for
  frameworks like NIST 800-53 / FedRAMP), customized per environment. A Config
  rule alerts; it does not stop a resource on its own.
- **Responsive controls.** Config findings feed SSM documents for optional
  auto-remediation. Auto-remediation is handled carefully — alert versus destroy
  is a deliberate matrix, not a default.
- **Preventive controls.** SCPs and RCPs set the **maximum** permission boundary
  in the organization (they do not grant rights). Example: deny S3 actions when
  `aws:SecureTransport` is off; tighten to specific TLS versions for FIPS needs.
- **Shift-left / policy-as-code.** Insert an OPA or CFN Guard stage into CI/CD
  to check infrastructure (Terraform / CloudFormation) before deploy. Terraform
  plans are converted to JSON and matched against policy; pass is silent, a
  violation can alert or block. Runs in the pipeline, pre-commit, or locally.

## How it maps to this framework

This repository is the **detective / evidentiary** layer: it turns live,
read-only AWS posture into a verified, machine-readable SDR checked against the
CR26 ruleset, and it deliberately never mutates resources or decides a status.

- Overlaps this repo already implements: continuous read-only evidence
  collection, custom Config rules feeding evidence, a readiness view, and (now)
  an OSCAL export of the SDR.
- Adjacent layers this repo intentionally does **not** own: preventive SCP/RCP
  enforcement and responsive SSM auto-remediation — folding those in would break
  the framework's "never mutate, never decide" trust boundary.
- The one aligned sibling added here: a shift-left OPA / CFN Guard example
  (`examples/shift-left/`) that checks IaC before deploy, sharing intent with
  the SDR without changing any SDR status.

## Source

Walkthrough by Sean McMahon, AWS Security Assurance Services (compliance
engineering). Distilled from the recorded overview; retained as reference
context for positioning the SDR framework within the full control stack.
