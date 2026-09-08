package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestIAMParseValid(t *testing.T) {
	t.Parallel()
	p := NewIAMParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "iam", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	first := resources[0]
	if first.Provider != models.ResourceTypeIAM {
		t.Errorf("Provider = %q, want %q", first.Provider, models.ResourceTypeIAM)
	}
	if first.Type != "Statement" {
		t.Errorf("Type = %q, want Statement", first.Type)
	}
	if first.Name != "AllowObjectRead" {
		t.Errorf("Name = %q, want AllowObjectRead", first.Name)
	}
	if got, ok := first.Properties["effect"].(string); !ok || got != "Allow" {
		t.Errorf("Properties[effect] = %v, want Allow", first.Properties["effect"])
	}
	actions, ok := first.Properties["action"].([]string)
	if !ok || len(actions) != 2 || actions[0] != "s3:GetObject" {
		t.Errorf("Properties[action] = %v, want two actions", first.Properties["action"])
	}
	if got := first.Metadata["statement_index"]; got != "0" {
		t.Errorf("Metadata[statement_index] = %q, want 0", got)
	}
	if got := first.Metadata["policy_id"]; got != "precept-read-policy" {
		t.Errorf("Metadata[policy_id] = %q, want precept-read-policy", got)
	}

	second := resources[1]
	// Single-string Action and Resource normalise to one-element lists.
	if action, ok := second.Properties["action"].([]string); !ok || len(action) != 1 || action[0] != "s3:DeleteObject" {
		t.Errorf("Properties[action] = %v, want single normalised action", second.Properties["action"])
	}
	if _, ok := second.Properties["condition"]; !ok {
		t.Error("Properties[condition] missing")
	}
	if got := second.Metadata["statement_index"]; got != "1" {
		t.Errorf("Metadata[statement_index] = %q, want 1", got)
	}
}

func TestIAMStatementAsObject(t *testing.T) {
	t.Parallel()
	data := `{"Version": "2012-10-17", "Statement": {"Sid": "only", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}}`
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewIAMParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("Parse() returned %d resources, want 1", len(resources))
	}
	if resources[0].Name != "only" {
		t.Errorf("Name = %q, want only", resources[0].Name)
	}
}

func TestIAMStatementWithoutSidGetsIndexedName(t *testing.T) {
	t.Parallel()
	data := `{"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}`
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewIAMParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if resources[0].Name != "statement-0" {
		t.Errorf("Name = %q, want statement-0", resources[0].Name)
	}
}

func TestIAMParseErrors(t *testing.T) {
	t.Parallel()
	p := NewIAMParser(0)
	write := func(t *testing.T, data string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}
		return path
	}

	tests := []struct {
		name      string
		path      string
		wantErr   error
		errSubstr string
	}{
		{name: "missing effect", path: filepath.Join("testdata", "iam", "invalid.json"), errSubstr: "effect"},
		{name: "malformed json", path: write(t, `{"Statement": [`), errSubstr: "invalid iam policy"},
		{name: "unknown top-level field", path: write(t, `{"Version": "2012-10-17", "Bogus": true, "Statement": []}`), errSubstr: "invalid iam policy"},
		{name: "unknown statement field", path: write(t, `{"Statement": [{"Effect": "Allow", "Action": "s3:Get", "Bogus": 1}]}`), errSubstr: "invalid iam policy"},
		{name: "missing statement", path: write(t, `{"Version": "2012-10-17"}`), wantErr: ErrMissingField},
		{name: "statement without action", path: write(t, `{"Statement": [{"Effect": "Allow", "Resource": "*"}]}`), errSubstr: "Action or NotAction"},
		{name: "invalid effect value", path: write(t, `{"Statement": [{"Effect": "allow", "Action": "s3:Get"}]}`), errSubstr: "effect"},
		{name: "action wrong type", path: write(t, `{"Statement": [{"Effect": "Allow", "Action": 42}]}`), errSubstr: "string or array"},
		{name: "empty file", path: filepath.Join("testdata", "iam", "empty.json"), wantErr: ErrEmptyFile},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resources, err := p.Parse(tt.path)
			if resources != nil {
				t.Errorf("Parse() resources = %v, want nil on error", resources)
			}
			if err == nil {
				t.Fatalf("Parse() error = nil, want error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse() error = %v, want %v", err, tt.wantErr)
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("Parse() error = %q, want containing %q", err.Error(), tt.errSubstr)
			}
		})
	}
}
