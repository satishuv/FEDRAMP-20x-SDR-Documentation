#!/usr/bin/env python3
"""Provider-deployed AWS Config custom rule: evidence-existence evaluator.

This is a SCAFFOLD a provider deploys in THEIR OWN account. It is NOT a
read-only collector in this repository and it does not run from this repo. It
exists because the Key Security Indicators in the Bucket B set are backed by
provider-produced evidence, a document, an artifact, or a reviewed-within-
interval process, that no plain AWS API exposes. A custom AWS Config rule
(this Lambda) is the honest way to make that evidence machine-checkable in the
provider's account.

What it evaluates. Given an Amazon S3 location for an evidence object and a
maximum age in days, it reports COMPLIANT when the object exists and was last
modified within the interval, and NON_COMPLIANT otherwise. Per-rule parameters
are supplied through the Config rule's InputParameters (see rules-manifest.json
for the 11 mappings). It reads only: s3:HeadObject / s3:GetObjectTagging.

What it deliberately does NOT do. It does not set an SDR implementation status,
it does not write an assessment, and it does not judge the CONTENT of the
evidence (whether a procedure is good, only that a current artifact exists).
A COMPLIANT result here is telemetry: it says an artifact is present and fresh,
which a human still reviews before drawing any compliance conclusion. This
preserves the same trust boundary as the rest of the framework.

Deploy: package with the AWS Config custom-rule pattern (an AWS::Config::
ConfigRule of Owner CUSTOM_LAMBDA pointing at this function). The provider owns
the S3 evidence bucket and the review cadence. See DEPLOY.md.

The handler logic is offline-testable: the S3 client is injected so a fake can
stand in, exactly like the read-only collectors' tests.
"""

import datetime
import json
import os


def evaluate_evidence(s3_client, bucket, key, max_age_days, now=None):
    """Pure evaluation: does the evidence object exist and is it fresh?

    Returns a dict {compliance_type, annotation}. compliance_type is one of
    COMPLIANT, NON_COMPLIANT, or NOT_APPLICABLE (when parameters are missing).
    No AWS Config specifics here so it can be unit tested in isolation.
    """
    if not bucket or not key:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "No evidence location configured for this rule.",
        }
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        head = s3_client.head_object(Bucket=bucket, Key=key)
    except Exception as e:  # noqa: BLE001 - missing object is the NON_COMPLIANT case
        name = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        if name in ("404", "NoSuchKey", "NotFound"):
            return {
                "compliance_type": "NON_COMPLIANT",
                "annotation": f"Evidence object s3://{bucket}/{key} does not exist.",
            }
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": f"Could not read evidence object ({name}).",
        }
    last_modified = head.get("LastModified")
    if last_modified is None:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": "Evidence object has no LastModified timestamp.",
        }
    if last_modified.tzinfo is None:
        last_modified = last_modified.replace(tzinfo=datetime.timezone.utc)
    age_days = (now - last_modified).days
    if max_age_days is not None and age_days > max_age_days:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": (
                f"Evidence object is {age_days} days old, older than the "
                f"{max_age_days}-day review interval."
            ),
        }
    return {
        "compliance_type": "COMPLIANT",
        "annotation": (
            f"Evidence object present and {age_days} days old, within the "
            f"{max_age_days}-day interval. Presence is telemetry; a human "
            "reviews the content."
        ),
    }


def _params(event):
    raw = event.get("ruleParameters") or "{}"
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def lambda_handler(event, context):  # noqa: ARG001 - context unused
    """AWS Config custom-rule entry point. Reads InputParameters
    (evidence_bucket, evidence_key, max_age_days) and reports compliance for
    the account. Requires boto3 at deploy time; imported lazily so this module
    imports cleanly for offline tests without boto3 installed."""
    import boto3  # noqa: PLC0415 - lazy import keeps the module offline-testable

    params = _params(event)
    result = evaluate_evidence(
        boto3.client("s3"),
        params.get("evidence_bucket"),
        params.get("evidence_key"),
        int(params["max_age_days"]) if params.get("max_age_days") else None,
    )

    invoking = json.loads(event.get("invokingEvent", "{}"))
    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": os.environ.get("ACCOUNT_ID", "account"),
            "ComplianceType": result["compliance_type"],
            "Annotation": result["annotation"][:256],
            "OrderingTimestamp": invoking.get(
                "notificationCreationTime",
                datetime.datetime.now(datetime.timezone.utc).isoformat()),
        }],
        ResultToken=event.get("resultToken", "TESTMODE"),
    )
    return result
