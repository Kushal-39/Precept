package precept.authz

admin_access_arn := "arn:aws:iam::aws:policy/AdministratorAccess"

iam_terraform_types := {
	"aws_iam_role",
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
}

as_array(x) := out if {
	is_string(x)
	out := [x]
} else := out if {
	is_array(x)
	out := x
} else := []

is_allow(props) if {
	not props.effect == "Deny"
}

deny contains {
	"rule_id": "IAM-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "IAM statement allows all actions with a wildcard",
	"remediation": "Replace wildcard actions with the explicit least-privilege set the workload needs",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	"*" in as_array(input.properties.action)
}

deny contains {
	"rule_id": "IAM-002",
	"severity": "CRITICAL",
	"score": 90,
	"resource": input.id,
	"description": "IAM statement applies to all resources with a wildcard",
	"remediation": "Scope the statement to specific resource ARNs",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	"*" in as_array(input.properties.resource)
}

has_admin_access if {
	_ := input.properties.resource
	contains(json.marshal(object.get(input.properties, "condition", null)), admin_access_arn)
}

has_admin_access if {
	_ := input.properties.resource
	contains(json.marshal(object.get(input.properties, "principal", null)), admin_access_arn)
}

deny contains {
	"rule_id": "IAM-003",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "IAM statement grants policy administration with AdministratorAccess, enabling privilege escalation",
	"remediation": "Remove iam:AttachRolePolicy or iam:PutRolePolicy combined with AdministratorAccess; grant scoped policy management instead",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	some a in as_array(input.properties.action)
	lower(a) in {"iam:attachrolepolicy", "iam:putrolepolicy"}
	has_admin_access
}

deny contains {
	"rule_id": "IAM-003",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "IAM statement grants policy administration with AdministratorAccess, enabling privilege escalation",
	"remediation": "Remove iam:AttachRolePolicy or iam:PutRolePolicy combined with AdministratorAccess; grant scoped policy management instead",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	some a in as_array(input.properties.action)
	lower(a) in {"iam:attachrolepolicy", "iam:putrolepolicy"}
	"*" in as_array(input.properties.resource)
}

deny contains {
	"rule_id": "IAM-004",
	"severity": "HIGH",
	"score": 80,
	"resource": input.id,
	"description": "IAM statement permits iam:PassRole on all resources",
	"remediation": "Restrict iam:PassRole to specific role ARNs the workload actually assumes",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	some a in as_array(input.properties.action)
	lower(a) == "iam:passrole"
	"*" in as_array(input.properties.resource)
}

deny contains {
	"rule_id": "IAM-005",
	"severity": "CRITICAL",
	"score": 92,
	"resource": input.id,
	"description": "IAM statement grants full iam:* on all resources",
	"remediation": "Split iam:* into the specific IAM actions the workload needs",
} if {
	input.provider == "iam"
	is_allow(input.properties)
	some a in as_array(input.properties.action)
	lower(a) == "iam:*"
	"*" in as_array(input.properties.resource)
}

embedded_wildcard_statement if {
	input.provider == "terraform"
	iam_terraform_types[input.type]
	some field in ["assume_role_policy", "policy"]
	raw := input.properties[field]
	is_string(raw)
	doc := json.unmarshal(raw)
	some stmt in as_array(doc.Statement)
	not stmt.Effect == "Deny"
	"*" in as_array(stmt.Action)
}

embedded_wildcard_statement if {
	input.provider == "terraform"
	iam_terraform_types[input.type]
	some field in ["assume_role_policy", "policy"]
	raw := input.properties[field]
	is_string(raw)
	doc := json.unmarshal(raw)
	some stmt in as_array(doc.Statement)
	not stmt.Effect == "Deny"
	"*" in as_array(stmt.Resource)
}

deny contains {
	"rule_id": "IAM-006",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "IAM policy embedded in Terraform grants wildcard administrative permissions",
	"remediation": "Replace wildcard permissions with least-privilege policies",
} if {
	embedded_wildcard_statement
}
