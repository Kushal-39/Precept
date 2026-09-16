package precept.authz

deny contains {
	"rule_id": "LOG-002",
	"severity": "MEDIUM",
	"score": 60,
	"resource": input.id,
	"description": "CloudWatch log group retention is shorter than 365 days",
	"remediation": "Set retention_in_days to at least 365 for audit-relevant log groups",
} if {
	input.provider == "terraform"
	input.type == "aws_cloudwatch_log_group"
	input.properties.retention_in_days < 365
}

deny contains {
	"rule_id": "LOG-003",
	"severity": "LOW",
	"score": 30,
	"resource": input.id,
	"description": "Log resource has no KMS encryption configured",
	"remediation": "Set kms_key_id to a customer-managed KMS key",
} if {
	input.provider == "terraform"
	input.type == "aws_cloudwatch_log_group"
	not input.properties.kms_key_id
}

deny contains {
	"rule_id": "LOG-003",
	"severity": "LOW",
	"score": 30,
	"resource": input.id,
	"description": "Log resource has no KMS encryption configured",
	"remediation": "Set kms_key_id to a customer-managed KMS key",
} if {
	input.provider == "terraform"
	input.type == "aws_cloudtrail"
	not input.properties.kms_key_id
}

has_cloudtrail if {
	some r in input.resources
	r.type == "aws_cloudtrail"
}

deny contains {
	"rule_id": "LOG-001",
	"severity": "HIGH",
	"score": 75,
	"resource": "corpus",
	"description": "No CloudTrail trail is defined anywhere in the scanned infrastructure",
	"remediation": "Add an aws_cloudtrail resource with multi-region logging and log file validation",
} if {
	count(input.resources) > 0
	not has_cloudtrail
}
