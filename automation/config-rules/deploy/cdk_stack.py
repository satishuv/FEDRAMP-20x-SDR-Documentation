#!/usr/bin/env python3
"""CDK v2 (Python) stack equivalent of cloudformation.yaml, generated from
rules-manifest.json by generate_templates.py. Do not edit by hand; re-run the
generator. A COMPLIANT result from these rules is telemetry, not a compliance
determination.
"""

import json
import os

from aws_cdk import App, Stack, CfnParameter, Duration
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_config as config
from constructs import Construct

MANIFEST = os.path.join(os.path.dirname(__file__), "..", "rules-manifest.json")


class EvidenceRulesStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        with open(MANIFEST, encoding="utf-8") as f:
            manifest = json.load(f)

        evidence_bucket = CfnParameter(self, "EvidenceBucket", type="String")
        code_bucket = CfnParameter(self, "LambdaCodeS3Bucket", type="String")
        code_key = CfnParameter(self, "LambdaCodeS3Key", type="String")

        role = iam.Role(
            self, "EvidenceRuleRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")],
        )
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:GetObjectTagging"],
            resources=[f"arn:aws:s3:::{{evidence_bucket.value_as_string}}/*"]))
        role.add_to_policy(iam.PolicyStatement(
            actions=["config:PutEvaluations"], resources=["*"]))

        code_src = s3.Bucket.from_bucket_name(
            self, "CodeBucket", code_bucket.value_as_string)
        fn = lambda_.Function(
            self, "EvidenceRuleFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler=manifest["meta"]["handler"],
            timeout=Duration.seconds(30),
            role=role,
            code=lambda_.Code.from_bucket(code_src, code_key.value_as_string),
        )
        fn.add_permission(
            "ConfigInvoke",
            principal=iam.ServicePrincipal("config.amazonaws.com"),
            action="lambda:InvokeFunction")

        for rule in manifest["rules"]:
            config.CfnConfigRule(
                self, _cdk_id(rule["rule_name"]),
                config_rule_name=rule["rule_name"],
                description=f"{{rule['ksi_id']}}: {{rule['evidence']}}",
                input_parameters={{
                    "evidence_bucket": evidence_bucket.value_as_string,
                    "evidence_key": f"{{rule['rule_name']}}/evidence",
                    "max_age_days": rule["default_max_age_days"],
                }},
                source=config.CfnConfigRule.SourceProperty(
                    owner="CUSTOM_LAMBDA",
                    source_identifier=fn.function_arn,
                    source_details=[config.CfnConfigRule.SourceDetailProperty(
                        event_source="aws.config",
                        message_type="ScheduledNotification",
                        maximum_execution_frequency="TwentyFour_Hours")]))


def _cdk_id(rule_name: str) -> str:
    return "".join(p.capitalize() for p in rule_name.split("-")) + "Rule"
