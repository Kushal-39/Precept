package precept.authz

import data.precept.authz.deny

short_retention := {
	"id": "aws_cloudwatch_log_group.a", "type": "aws_cloudwatch_log_group",
	"name": "a", "provider": "terraform",
	"properties": {"retention_in_days": 7},
}

test_log_002_short_retention if {
	some f in deny with input as short_retention
	f.rule_id == "LOG-002"
	f.severity == "MEDIUM"
	f.score == 60
}

test_log_002_boundary_retention_clean if {
	lg := {
		"id": "aws_cloudwatch_log_group.a", "type": "aws_cloudwatch_log_group",
		"name": "a", "provider": "terraform",
		"properties": {"retention_in_days": 365, "kms_key_id": "arn:aws:kms:us:k:key"},
	}
	not "LOG-002" in {f.rule_id | some f in deny with input as lg}
}

test_log_002_missing_retention_clean if {
	lg := {
		"id": "aws_cloudwatch_log_group.a", "type": "aws_cloudwatch_log_group",
		"name": "a", "provider": "terraform",
		"properties": {"kms_key_id": "arn:aws:kms:us:k:key"},
	}
	not "LOG-002" in {f.rule_id | some f in deny with input as lg}
}

test_log_003_group_missing_kms if {
	some f in deny with input as short_retention
	f.rule_id == "LOG-003"
	f.severity == "LOW"
}

test_log_003_trail_missing_kms if {
	trail := {
		"id": "aws_cloudtrail.t", "type": "aws_cloudtrail", "name": "t", "provider": "terraform",
		"properties": {},
	}
	some f in deny with input as trail
	f.rule_id == "LOG-003"
}

test_log_003_trail_with_kms_clean if {
	trail := {
		"id": "aws_cloudtrail.t", "type": "aws_cloudtrail", "name": "t", "provider": "terraform",
		"properties": {"kms_key_id": "arn:aws:kms:us:k:key"},
	}
	count([f | some f in deny with input as trail]) == 0
}

test_log_001_no_trail_in_corpus if {
	corpus := {"resources": [{"id": "a", "type": "aws_s3_bucket"}]}
	some f in deny with input as corpus
	f.rule_id == "LOG-001"
	f.resource == "corpus"
	f.severity == "HIGH"
}

test_log_001_trail_present_clean if {
	corpus := {"resources": [{"id": "t", "type": "aws_cloudtrail"}]}
	not "LOG-001" in {f.rule_id | some f in deny with input as corpus}
}

test_log_001_empty_corpus_clean if {
	count([f | some f in deny with input as {"resources": []}]) == 0
}
