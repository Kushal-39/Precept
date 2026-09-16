package precept.authz

public_acls := {"public-read", "public-read-write", "authenticated-read"}

deny contains {
	"rule_id": "STO-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "S3 bucket allows public access",
	"remediation": "Enable all four S3 public access block settings and scope bucket policies to known principals",
} if {
	input.provider == "terraform"
	input.type == "aws_s3_bucket"
	input.properties.publicly_accessible == true
}

deny contains {
	"rule_id": "STO-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "S3 bucket allows public access",
	"remediation": "Enable all four S3 public access block settings and scope bucket policies to known principals",
} if {
	input.provider == "terraform"
	input.type == "aws_s3_bucket"
	public_acls[input.properties.acl]
}

deny contains {
	"rule_id": "STO-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "S3 bucket allows public access",
	"remediation": "Enable all four S3 public access block settings and scope bucket policies to known principals",
} if {
	input.provider == "terraform"
	input.type == "aws_s3_bucket_public_access_block"
	some flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	input.properties[flag] == false
}

deny contains {
	"rule_id": "STO-002",
	"severity": "HIGH",
	"score": 75,
	"resource": input.id,
	"description": "S3 bucket has no server-side encryption configuration",
	"remediation": "Add a server_side_encryption_configuration block enforcing SSE-S3 or SSE-KMS",
} if {
	input.provider == "terraform"
	input.type == "aws_s3_bucket"
	not input.properties.server_side_encryption_configuration
}

deny contains {
	"rule_id": "STO-003",
	"severity": "MEDIUM",
	"score": 45,
	"resource": input.id,
	"description": "S3 bucket has no access logging configured",
	"remediation": "Add a logging block pointing at a dedicated log bucket",
} if {
	input.provider == "terraform"
	input.type == "aws_s3_bucket"
	not input.properties.logging
}
