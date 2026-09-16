package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func mustResource(t *testing.T, id, typ, name, provider string, props map[string]any) *models.Resource {
	t.Helper()
	r, err := models.NewResource(id, typ, name, provider, props)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewEngineRealPolicies(t *testing.T) {
	engine, err := NewEngine("../../policies")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(engine.Files()) != 4 {
		t.Errorf("got %d policy files, want 4", len(engine.Files()))
	}
	files := engine.Files()
	files[0] = "mutated"
	if engine.Files()[0] == "mutated" {
		t.Error("Files should return a copy")
	}
	r := mustResource(t, "p#0", "Statement", "s", "iam", map[string]any{
		"effect": "Allow", "action": []string{"*"}, "resource": []string{"*"},
	})
	findings, err := engine.Evaluate(r)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	if !ids["IAM-001"] || !ids["IAM-002"] {
		t.Errorf("expected IAM-001 and IAM-002, got %+v", findings)
	}
}

func TestNewEngineErrors(t *testing.T) {
	malformed := t.TempDir()
	writePolicy(t, malformed, "bad.rego", "package precept.authz\ndeny contains {\n")

	empty := t.TempDir()

	tests := []struct {
		name string
		dir  string
	}{
		{"empty path", ""},
		{"missing dir", filepath.Join(t.TempDir(), "nope")},
		{"empty dir", empty},
		{"malformed rego", malformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewEngine(tt.dir); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("file not dir", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "f.rego")
		if err := os.WriteFile(f, []byte(goodPolicy), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewEngine(f); err == nil {
			t.Fatal("expected error for file path")
		}
	})
	t.Run("test files excluded", func(t *testing.T) {
		dir := t.TempDir()
		writePolicy(t, dir, "only.rego", "package precept.authz\n")
		if err := os.WriteFile(filepath.Join(dir, "x_test.rego"), []byte("package precept.authz\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewEngine(dir); err != nil {
			t.Fatalf("test files should be ignored: %v", err)
		}
	})
	t.Run("nested discovery", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		writePolicy(t, sub, "nested.rego", goodPolicy)
		engine, err := NewEngine(dir)
		if err != nil {
			t.Fatalf("nested policies should load: %v", err)
		}
		if len(engine.Files()) != 1 {
			t.Fatalf("got %d files, want 1", len(engine.Files()))
		}
	})
}

func TestEvaluateTable(t *testing.T) {
	engine, err := NewEngine("../../policies")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tests := []struct {
		name     string
		resource *models.Resource
		wantIDs  []string
		wantNone []string
	}{
		{
			name:     "wildcard admin",
			resource: mustResource(t, "p#0", "Statement", "s", "iam", map[string]any{"effect": "Allow", "action": []string{"*"}, "resource": []string{"*"}}),
			wantIDs:  []string{"IAM-001", "IAM-002"},
		},
		{
			name:     "deny ignored",
			resource: mustResource(t, "p#1", "Statement", "s", "iam", map[string]any{"effect": "Deny", "action": []string{"*"}, "resource": []string{"*"}}),
			wantNone: []string{"IAM-001", "IAM-002"},
		},
		{
			name:     "passrole",
			resource: mustResource(t, "p#2", "Statement", "s", "iam", map[string]any{"effect": "Allow", "action": []string{"iam:PassRole"}, "resource": []string{"*"}}),
			wantIDs:  []string{"IAM-004"},
		},
		{
			name:     "public bucket",
			resource: mustResource(t, "b", "aws_s3_bucket", "b", "terraform", map[string]any{"acl": "public-read"}),
			wantIDs:  []string{"STO-001", "STO-002", "STO-003"},
		},
		{
			name:     "open ssh",
			resource: mustResource(t, "sg", "aws_security_group", "s", "terraform", map[string]any{"ingress": []any{map[string]any{"from_port": float64(22), "to_port": float64(22), "cidr_blocks": []any{"0.0.0.0/0"}}}}),
			wantIDs:  []string{"NET-001"},
		},
		{
			name:     "short retention",
			resource: mustResource(t, "lg", "aws_cloudwatch_log_group", "l", "terraform", map[string]any{"retention_in_days": float64(7)}),
			wantIDs:  []string{"LOG-002", "LOG-003"},
		},
		{
			name:     "compliant bucket",
			resource: mustResource(t, "b", "aws_s3_bucket", "b", "terraform", map[string]any{"acl": "private", "server_side_encryption_configuration": map[string]any{"x": 1}, "logging": map[string]any{"y": 1}}),
			wantNone: []string{"STO-001", "STO-002", "STO-003"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := engine.Evaluate(tt.resource)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			ids := map[string]bool{}
			for _, f := range findings {
				ids[f.RuleID] = true
			}
			for _, want := range tt.wantIDs {
				if !ids[want] {
					t.Errorf("missing %s in %+v", want, findings)
				}
			}
			for _, none := range tt.wantNone {
				if ids[none] {
					t.Errorf("unexpected %s in %+v", none, findings)
				}
			}
		})
	}
}

func TestEvaluateFailClosed(t *testing.T) {
	engine, err := NewEngine("../../policies")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, err := engine.Evaluate(nil); err == nil {
		t.Error("nil resource should fail closed")
	}
	bad, _ := models.NewResource("x", "Statement", "s", "iam", map[string]any{})
	bad.ID = ""
	if _, err := engine.Evaluate(bad); err == nil {
		t.Error("empty resource ID should fail closed")
	}
}

func TestEvaluateUndefinedDeniesClosed(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "other.rego", "package other\n\nallow if {\n\tinput.provider == \"terraform\"\n}\n")
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := mustResource(t, "x", "aws_s3_bucket", "b", "terraform", map[string]any{})
	if _, err := engine.Evaluate(r); err == nil {
		t.Fatal("undefined deny result should fail closed")
	}
}

func TestEvaluateRejectsMalformedPolicyOutput(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "bad.rego", `package precept.authz

deny contains {"rule_id": "T-001", "severity": "BOGUS", "score": 10, "resource": input.id, "description": "d", "remediation": "m"} if {
	input.provider == "terraform"
}
`)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := mustResource(t, "x", "aws_s3_bucket", "b", "terraform", map[string]any{})
	if _, err := engine.Evaluate(r); err == nil {
		t.Fatal("invalid severity in policy output should fail closed")
	}
}

func TestEvaluateCorpus(t *testing.T) {
	engine, err := NewEngine("../../policies")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bucket := mustResource(t, "b", "aws_s3_bucket", "b", "terraform", map[string]any{})
	findings, err := engine.EvaluateCorpus([]*models.Resource{bucket})
	if err != nil {
		t.Fatalf("EvaluateCorpus: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "LOG-001" && f.Resource == "corpus" {
			found = true
		}
		if strings.HasPrefix(f.RuleID, "IAM-") || strings.HasPrefix(f.RuleID, "NET-") || strings.HasPrefix(f.RuleID, "STO-") {
			t.Errorf("corpus evaluation should not emit per-resource rule %s", f.RuleID)
		}
	}
	if !found {
		t.Error("expected LOG-001 for corpus without CloudTrail")
	}
	trail := mustResource(t, "tr", "aws_cloudtrail", "t", "terraform", map[string]any{"kms_key_id": "k"})
	findings, err = engine.EvaluateCorpus([]*models.Resource{bucket, trail})
	if err != nil {
		t.Fatalf("EvaluateCorpus: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "LOG-001" {
			t.Errorf("LOG-001 should not fire with a trail present: %+v", f)
		}
	}
	empty, err := engine.EvaluateCorpus([]*models.Resource{})
	if err != nil {
		t.Fatalf("empty corpus: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty corpus should yield no findings, got %+v", empty)
	}
	if _, err := engine.EvaluateCorpus(nil); err == nil {
		t.Error("nil corpus should fail closed")
	}
}
