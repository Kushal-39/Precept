package precept.authz

import data.precept.authz.deny

allow_admin := {
	"id": "p#0",
	"type": "Statement",
	"name": "admin",
	"provider": "iam",
	"properties": {"effect": "Allow", "action": ["*"], "resource": ["*"]},
}

deny_admin := {
	"id": "p#0",
	"type": "Statement",
	"name": "admin",
	"provider": "iam",
	"properties": {"effect": "Deny", "action": ["*"], "resource": ["*"]},
}

test_iam_001_wildcard_action if {
	some f in deny with input as allow_admin
	f.rule_id == "IAM-001"
	f.severity == "CRITICAL"
	f.score == 95
}

test_iam_001_ignored_for_deny if {
	count([f | some f in deny with input as deny_admin]) == 0
}

test_iam_001_absent_for_scoped_action if {
	scoped := {
		"id": "p#1", "type": "Statement", "name": "s", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["s3:GetObject"], "resource": ["arn:aws:s3:::b/*"]},
	}
	not "IAM-001" in {f.rule_id | some f in deny with input as scoped}
}

test_iam_002_wildcard_resource if {
	some f in deny with input as allow_admin
	f.rule_id == "IAM-002"
}

test_iam_003_escalation_admin_arn if {
	stmt := {
		"id": "p#2", "type": "Statement", "name": "e", "provider": "iam",
		"properties": {
			"effect": "Allow",
			"action": ["iam:AttachRolePolicy"],
			"resource": ["arn:aws:iam::123:role/x"],
			"condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
		},
	}
	some f in deny with input as stmt
	f.rule_id == "IAM-003"
}

test_iam_003_escalation_wildcard_resource if {
	stmt := {
		"id": "p#3", "type": "Statement", "name": "e", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["iam:PutRolePolicy"], "resource": ["*"]},
	}
	some f in deny with input as stmt
	f.rule_id == "IAM-003"
}

test_iam_003_absent_without_admin_or_wildcard if {
	stmt := {
		"id": "p#4", "type": "Statement", "name": "e", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["iam:AttachRolePolicy"], "resource": ["arn:aws:iam::123:role/x"]},
	}
	not "IAM-003" in {f.rule_id | some f in deny with input as stmt}
}

test_iam_004_passrole_wildcard if {
	stmt := {
		"id": "p#5", "type": "Statement", "name": "p", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["iam:PassRole"], "resource": ["*"]},
	}
	some f in deny with input as stmt
	f.rule_id == "IAM-004"
	f.severity == "HIGH"
}

test_iam_004_absent_for_scoped_passrole if {
	stmt := {
		"id": "p#6", "type": "Statement", "name": "p", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["iam:PassRole"], "resource": ["arn:aws:iam::123:role/x"]},
	}
	not "IAM-004" in {f.rule_id | some f in deny with input as stmt}
}

test_iam_005_full_admin if {
	stmt := {
		"id": "p#7", "type": "Statement", "name": "f", "provider": "iam",
		"properties": {"effect": "Allow", "action": ["iam:*"], "resource": ["*"]},
	}
	some f in deny with input as stmt
	f.rule_id == "IAM-005"
}

test_iam_006_embedded_terraform_policy if {
	tf := {
		"id": "aws_iam_policy.wild", "type": "aws_iam_policy", "name": "wild", "provider": "terraform",
		"properties": {"policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"},
	}
	some f in deny with input as tf
	f.rule_id == "IAM-006"
	f.resource == "aws_iam_policy.wild"
}

test_iam_006_ignored_for_deny_embedded if {
	tf := {
		"id": "aws_iam_policy.d", "type": "aws_iam_policy", "name": "d", "provider": "terraform",
		"properties": {"policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Deny\", \"Action\": \"*\", \"Resource\": \"*\"}]}"},
	}
	not "IAM-006" in {f.rule_id | some f in deny with input as tf}
}

test_iam_006_ignored_for_malformed_embedded if {
	tf := {
		"id": "aws_iam_policy.b", "type": "aws_iam_policy", "name": "b", "provider": "terraform",
		"properties": {"policy": "not-json"},
	}
	not "IAM-006" in {f.rule_id | some f in deny with input as tf}
}

test_iam_006_ignored_for_other_types if {
	tf := {
		"id": "aws_s3_bucket.b", "type": "aws_s3_bucket", "name": "b", "provider": "terraform",
		"properties": {"policy": "{\"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"},
	}
	not "IAM-006" in {f.rule_id | some f in deny with input as tf}
}

test_iam_missing_fields_no_findings if {
	bare := {"id": "p#8", "type": "Statement", "name": "b", "provider": "iam", "properties": {"effect": "Allow"}}
	count([f | some f in deny with input as bare]) == 0
}

test_iam_wrong_provider_no_findings if {
	k8s := {
		"id": "pod", "type": "Pod", "name": "p", "provider": "kubernetes",
		"properties": {"effect": "Allow", "action": ["*"], "resource": ["*"]},
	}
	count([f | some f in deny with input as k8s]) == 0
}
