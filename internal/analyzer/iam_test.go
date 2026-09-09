package analyzer

import (
	"testing"

	"github.com/precept/precept/internal/models"
)

func iamResource(t *testing.T, props map[string]any) *models.Resource {
	t.Helper()
	r, err := models.NewResource("policy.json#0", "Statement", "stmt", "iam", props)
	if err != nil {
		t.Fatalf("NewResource error: %v", err)
	}
	return r
}

func ruleIDs(findings []*models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

func TestIAMWildcardAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		props     map[string]any
		wantRules []string
	}{
		{
			name:      "single wildcard action",
			props:     map[string]any{"effect": "Allow", "action": "*", "resource": "arn:aws:s3:::bucket/*"},
			wantRules: []string{RuleIAMWildcardAdmin},
		},
		{
			name:      "wildcard in array",
			props:     map[string]any{"effect": "Allow", "action": []string{"s3:GetObject", "*"}, "resource": "arn"},
			wantRules: []string{RuleIAMWildcardAdmin},
		},
		{
			name:      "wildcard action and resource",
			props:     map[string]any{"effect": "Allow", "action": "*", "resource": "*"},
			wantRules: []string{RuleIAMWildcardAdmin, RuleIAMWildcardRes},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := NewIAMAnalyzer().Analyze(iamResource(t, tt.props))
			got := ruleIDs(findings)
			if len(got) != len(tt.wantRules) {
				t.Fatalf("rules = %v, want %v", got, tt.wantRules)
			}
			for i, want := range tt.wantRules {
				if got[i] != want {
					t.Errorf("rules[%d] = %q, want %q", i, got[i], want)
				}
			}
			for _, f := range findings {
				if f.Severity != models.SeverityCritical {
					t.Errorf("wildcard finding severity = %q, want CRITICAL", f.Severity)
				}
				if f.Remediation == "" || f.Description == "" {
					t.Errorf("finding missing description/remediation: %+v", f)
				}
			}
		})
	}
}

func TestIAMDenyExempt(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{"effect": "Deny", "action": "*", "resource": "*"})
	if findings := NewIAMAnalyzer().Analyze(res); len(findings) != 0 {
		t.Errorf("Deny statement produced %d findings, want 0", len(findings))
	}
}

func TestIAMNoFindingsOnCleanStatement(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{
		"effect": "Allow", "action": []string{"s3:GetObject"}, "resource": []string{"arn:aws:s3:::b/*"},
	})
	if findings := NewIAMAnalyzer().Analyze(res); len(findings) != 0 {
		t.Errorf("clean statement produced %v, want none", ruleIDs(findings))
	}
}

func TestIAMEscalation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		props map[string]any
	}{
		{
			name: "attach role policy with admin access via condition",
			props: map[string]any{
				"effect": "Allow", "action": "iam:AttachRolePolicy", "resource": "arn:aws:iam::123:role/x",
				"condition": map[string]any{"ArnEquals": map[string]any{"aws:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"}},
			},
		},
		{
			name:  "attach role policy with wildcard resource",
			props: map[string]any{"effect": "Allow", "action": "iam:AttachRolePolicy", "resource": "*"},
		},
		{
			name:  "put role policy with wildcard",
			props: map[string]any{"effect": "Allow", "action": []string{"iam:PutRolePolicy"}, "resource": "*"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := NewIAMAnalyzer().Analyze(iamResource(t, tt.props))
			if !containsString(ruleIDs(findings), RuleIAMEscalation) {
				t.Errorf("rules = %v, want %s", ruleIDs(findings), RuleIAMEscalation)
			}
		})
	}
}

func TestIAMPassRoleWildcard(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{"effect": "Allow", "action": "iam:PassRole", "resource": "*"})
	findings := NewIAMAnalyzer().Analyze(res)
	if !containsString(ruleIDs(findings), RuleIAMPassRole) {
		t.Errorf("rules = %v, want %s", ruleIDs(findings), RuleIAMPassRole)
	}
	for _, f := range findings {
		if f.RuleID == RuleIAMPassRole && f.Severity != models.SeverityHigh {
			t.Errorf("PassRole severity = %q, want HIGH", f.Severity)
		}
	}
}

func TestIAMPassRoleScopedNoFinding(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{"effect": "Allow", "action": "iam:PassRole", "resource": "arn:aws:iam::123:role/deployer"})
	if findings := NewIAMAnalyzer().Analyze(res); len(findings) != 0 {
		t.Errorf("scoped PassRole produced %v, want none", ruleIDs(findings))
	}
}

func TestIAMFullAdmin(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{"effect": "Allow", "action": []string{"iam:*"}, "resource": "*"})
	findings := NewIAMAnalyzer().Analyze(res)
	if !containsString(ruleIDs(findings), RuleIAMFullAdmin) {
		t.Errorf("rules = %v, want %s", ruleIDs(findings), RuleIAMFullAdmin)
	}
}

func TestIAMActionCaseInsensitive(t *testing.T) {
	t.Parallel()
	res := iamResource(t, map[string]any{"effect": "Allow", "action": []string{"IAM:PASSROLE"}, "resource": "*"})
	findings := NewIAMAnalyzer().Analyze(res)
	if !containsString(ruleIDs(findings), RuleIAMPassRole) {
		t.Errorf("rules = %v, want %s (action matching must be case-insensitive)", ruleIDs(findings), RuleIAMPassRole)
	}
}

func TestIAMMalformedProperties(t *testing.T) {
	t.Parallel()
	analyzer := NewIAMAnalyzer()
	tests := []struct {
		name  string
		props map[string]any
	}{
		{name: "nil properties", props: nil},
		{name: "empty properties", props: map[string]any{}},
		{name: "empty strings", props: map[string]any{"effect": "", "action": "", "resource": ""}},
		{name: "wrong types", props: map[string]any{"effect": 3, "action": 1.5, "resource": true}},
		{name: "mixed type list", props: map[string]any{"effect": "Allow", "action": []any{"*", 42, nil}, "resource": []any{7}}},
		{name: "missing effect", props: map[string]any{"action": "*", "resource": "*"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := models.NewResource("res", "Statement", "n", "iam", tt.props)
			if err != nil {
				t.Fatalf("NewResource error: %v", err)
			}
			findings := analyzer.Analyze(r)
			for _, f := range findings {
				if f == nil {
					t.Error("analyzer emitted nil finding")
				}
			}
		})
	}
}

func terraformIAMResource(t *testing.T, resourceType string, props map[string]any) *models.Resource {
	t.Helper()
	r, err := models.NewResource(resourceType+".app", resourceType, "app", "terraform", props)
	if err != nil {
		t.Fatalf("NewResource error: %v", err)
	}
	return r
}

const wildcardPolicy = `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}`

func TestIAMEmbeddedTerraformPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		resourceTyp string
		props       map[string]any
		wantFinding bool
	}{
		{name: "role with wildcard assume policy", resourceTyp: "aws_iam_role", props: map[string]any{"assume_role_policy": wildcardPolicy}, wantFinding: true},
		{name: "policy with wildcard", resourceTyp: "aws_iam_policy", props: map[string]any{"policy": wildcardPolicy}, wantFinding: true},
		{name: "role policy clean", resourceTyp: "aws_iam_role_policy",
			props: map[string]any{"policy": `{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}`}},
		{name: "unparseable policy skipped", resourceTyp: "aws_iam_role", props: map[string]any{"assume_role_policy": "{broken"}},
		{name: "not an iam resource", resourceTyp: "aws_s3_bucket", props: map[string]any{"policy": wildcardPolicy}},
		{name: "empty policy string", resourceTyp: "aws_iam_role", props: map[string]any{"assume_role_policy": "  "}},
		{name: "deny only policy", resourceTyp: "aws_iam_role",
			props: map[string]any{"assume_role_policy": `{"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}`}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := NewIAMAnalyzer().Analyze(terraformIAMResource(t, tt.resourceTyp, tt.props))
			if (len(findings) > 0) != tt.wantFinding {
				t.Errorf("Analyze() = %d findings, wantFinding %v (%v)", len(findings), tt.wantFinding, ruleIDs(findings))
			}
			for _, f := range findings {
				if f.Resource != tt.resourceTyp+".app" {
					t.Errorf("finding attributed to %q, want the Terraform resource ID", f.Resource)
				}
				if f.RuleID != RuleIAMTerraformPolicy {
					t.Errorf("rule = %q, want %s", f.RuleID, RuleIAMTerraformPolicy)
				}
			}
		})
	}
}

func containsString(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
