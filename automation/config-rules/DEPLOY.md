# Provider-deployed Config custom rules (Bucket B)

These are AWS Config custom rules a provider deploys in their own account. They
are NOT read-only collectors in this repository, and they do not run from here.

## Why these exist

Eleven Key Security Indicators are backed by provider-produced evidence: a
document, an artifact, or a reviewed-within-interval process (a training record,
a change-management procedure, an after-action report, a recovery plan, and so
on). No plain AWS API exposes that evidence, so a read-only collector cannot
gather it honestly. The honest mechanism is a custom AWS Config rule the
provider deploys, which checks that the evidence artifact exists in a known
Amazon S3 location and is current within a review interval.

## What the rule reports, and what it does not

- Reports COMPLIANT when the evidence object exists and is fresh; NON_COMPLIANT
  when it is missing or stale; NOT_APPLICABLE when no location is configured.
- A COMPLIANT result is telemetry: an artifact is present and current. It is
  NOT a compliance determination, NOT a source-eligibility decision, and NOT an
  assessment. A human still reviews the content and takes ownership.
- The rule never sets an SDR implementation status and never writes an
  assessment. Same trust boundary as the rest of the framework.
- It checks presence and freshness, never the quality of the content.

## Files

- `evidence_existence_rule.py` — the shared, parameterized Lambda handler. Its
  `evaluate_evidence` function is pure and offline-testable.
- `rules-manifest.json` — the 11 KSI-to-rule mappings, each with a suggested
  default review interval the provider confirms against their own policy.
- `test_evidence_existence_rule.py` — offline tests of the handler logic.

## Deploy (per rule)

1. Package `evidence_existence_rule.py` as a Lambda function.
2. Create an `AWS::Config::ConfigRule` with `Owner: CUSTOM_LAMBDA` pointing at
   the function, with `InputParameters`:
   `{"evidence_bucket": "<your-bucket>", "evidence_key": "<path/to/artifact>", "max_age_days": <interval>}`.
3. Grant the Lambda read-only `s3:GetObject`/`s3:HeadObject` on the evidence
   object and `config:PutEvaluations`.
4. The provider owns the evidence bucket and the review cadence.

The default `max_age_days` values in the manifest are suggestions, not asserted
FedRAMP-required intervals. Confirm each against your own policy and the
applicable FedRAMP interval before relying on it.
