package precept.authz

import data.precept.authz.deny

public_bucket := {
	"id": "aws_s3_bucket.p", "type": "aws_s3_bucket", "name": "p", "provider": "terraform",
	"properties": {"acl": "public-read"},
}

test_sto_001_public_acl if {
	some f in deny with input as public_bucket
	f.rule_id == "STO-001"
	f.severity == "CRITICAL"
}

test_sto_001_public_flag if {
	b := {
		"id": "aws_s3_bucket.p", "type": "aws_s3_bucket", "name": "p", "provider": "terraform",
		"properties": {"publicly_accessible": true},
	}
	some f in deny with input as b
	f.rule_id == "STO-001"
}

test_sto_001_private_bucket_clean if {
	b := {
		"id": "aws_s3_bucket.p", "type": "aws_s3_bucket", "name": "p", "provider": "terraform",
		"properties": {
			"acl": "private",
			"server_side_encryption_configuration": {"rule": "x"},
			"logging": {"target_bucket": "logs"},
		},
	}
	count([f | some f in deny with input as b]) == 0
}

test_sto_001_open_access_block if {
	b := {
		"id": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block",
		"name": "b", "provider": "terraform",
		"properties": {
			"block_public_acls": true, "block_public_policy": false,
			"ignore_public_acls": true, "restrict_public_buckets": true,
		},
	}
	some f in deny with input as b
	f.rule_id == "STO-001"
}

test_sto_001_closed_access_block_clean if {
	b := {
		"id": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block",
		"name": "b", "provider": "terraform",
		"properties": {
			"block_public_acls": true, "block_public_policy": true,
			"ignore_public_acls": true, "restrict_public_buckets": true,
		},
	}
	count([f | some f in deny with input as b]) == 0
}

test_sto_002_missing_encryption if {
	some f in deny with input as public_bucket
	f.rule_id == "STO-002"
	f.severity == "HIGH"
}

test_sto_003_missing_logging if {
	some f in deny with input as public_bucket
	f.rule_id == "STO-003"
	f.severity == "MEDIUM"
}
