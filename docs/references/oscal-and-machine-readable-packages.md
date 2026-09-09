# Reference: OSCAL and machine-readable authorization packages

Reference context on OSCAL (Open Security Controls Assessment Language) and the
machine-readable direction of FedRAMP, gathered from primary sources. This is
reference material for positioning the framework's OSCAL export, not a FedRAMP
requirement statement.

## OSCAL in brief

OSCAL is a NIST project (developed with FedRAMP since 2016) that provides a
standardized, machine-readable representation of security documentation and
assessment information, so that governance/risk/compliance (GRC) tools can
ingest it directly instead of parsing prose documents.

## First OSCAL SSP submission (AWS, 2022)

AWS was the first cloud service provider to produce an OSCAL-formatted System
Security Plan (SSP) for the FedRAMP PMO, ingested by a partner GRC tool (Xacta).
The stated value was cutting the manual review and transcription effort that
makes up much of the roughly 4,200 workforce hours estimated for an ATO.

Source: AWS Security Blog, "AWS achieves the first OSCAL format system security
plan submission to FedRAMP" (Matthew Donkin, 30 June 2022),
https://aws.amazon.com/blogs/security/aws-achieves-the-first-oscal-format-system-security-plan-submission-to-fedramp/

## RFC-0024 (Rev5 machine-readable packages)

FedRAMP RFC-0024 requires machine-readable authorization packages for the Rev5
process, and lists approved formats including OSCAL. Two facts from the primary
text worth keeping straight:

- RFC-0024 states it "applies only to the FedRAMP Rev5 process and does not
  apply to FedRAMP 20x."
- Its approved-formats requirement (LMR-FRX-LAF) names OSCAL as one approved
  format and explicitly says there is no single universal format, since
  structured formats are machine-interchangeable.

Source: FedRAMP RFC-0024, https://fedramp.gov/rfcs/0024

## Why this framework offers an OSCAL export anyway

The SDR is already a schema-valid, machine-readable JSON artifact. The OSCAL
export (see `docs/oscal-export.md`) is offered as an **interoperability
convenience**: it makes the same verified SDR facts available in OSCAL for any
downstream GRC tool or trust center that prefers to ingest OSCAL. The export
makes no claim about whether any particular FedRAMP process requires OSCAL; it
simply provides the option.
