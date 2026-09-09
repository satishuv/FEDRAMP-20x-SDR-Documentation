# Shift-left policy: S3 buckets must enforce TLS/SSL in transit.
#
# This is the CI/CD "policy as code" sibling to the SDR framework. Where the
# SDR verifies a FINISHED record against the CR26 ruleset, this checks
# INFRASTRUCTURE-as-code BEFORE it is deployed, in the same spirit as the
# AWS Security Assurance Services compliance-engineering demo (CFN Guard / OPA
# stage in the pipeline). Pass is silent; a violation is reported and can block
# the deploy.
#
# Input: the JSON form of a `terraform show -json` plan (or any resource list
# with the same shape). The runner also accepts a simplified {"resources": []}
# shape for local checks.
#
# Intent alignment: this maps to the same encryption-in-transit outcome the SDR
# tracks (KSI-CNA / SC-8, SC-13 family). It does NOT set an SDR status; it is a
# pre-deploy gate that produces its own pass/fail, optionally emitting evidence.
#
# Run with: opa eval -d s3_tls.rego -i plan.json "data.shiftleft.s3.deny"

package shiftleft.s3

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Collect S3 bucket resources from either a terraform plan
# (planned_values.root_module.resources) or a simplified resource list.
_buckets contains r if {
	some r in input.resources
	r.type == "aws_s3_bucket"
}

_buckets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
}

# The set of bucket names that DO have an SSL/TLS-enforcing policy attached.
_buckets_with_tls contains name if {
	some p in _policies
	name := p.values.bucket
	_policy_enforces_tls(p.values.policy)
}

_policies contains r if {
	some r in input.resources
	r.type == "aws_s3_bucket_policy"
}

_policies contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_policy"
}

# A policy enforces TLS if it denies requests where aws:SecureTransport is false.
_policy_enforces_tls(policy_json) if {
	policy := json.unmarshal(policy_json)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

# Deny any bucket that has no TLS-enforcing policy.
deny contains msg if {
	some b in _buckets
	name := b.values.bucket
	not name in _buckets_with_tls
	msg := sprintf("S3 bucket '%s' has no policy denying non-TLS (aws:SecureTransport=false) access", [name])
}

# Convenience: overall allow is true only when there are no denials.
default allow := false

allow if {
	count(deny) == 0
}
