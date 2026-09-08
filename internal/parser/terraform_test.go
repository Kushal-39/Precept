package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestTerraformSupportedExtensions(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	got := p.SupportedExtensions()
	for _, want := range []string{".tfstate", ".tf.json", ".tfstate.json"} {
		if !contains(got, want) {
			t.Errorf("SupportedExtensions() missing %q in %v", want, got)
		}
	}
}

func TestTerraformParseState(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "terraform", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	first := resources[0]
	if first.ID != "aws_s3_bucket.data" {
		t.Errorf("ID = %q, want %q", first.ID, "aws_s3_bucket.data")
	}
	if first.Type != "aws_s3_bucket" || first.Name != "data" {
		t.Errorf("Type/Name = %q/%q, want aws_s3_bucket/data", first.Type, first.Name)
	}
	if first.Provider != models.ResourceTypeTerraform {
		t.Errorf("Provider = %q, want %q", first.Provider, models.ResourceTypeTerraform)
	}
	if first.Properties["bucket"] != "precept-data" || first.Properties["acl"] != "private" {
		t.Errorf("Properties = %v, want bucket and acl", first.Properties)
	}
	if first.Metadata["file"] == "" {
		t.Error("Metadata[file] not set")
	}
	if first.Metadata["terraform_provider"] != "registry.terraform.io/hashicorp/aws" {
		t.Errorf("Metadata[terraform_provider] = %q", first.Metadata["terraform_provider"])
	}
	if first.Metadata["terraform_mode"] != "managed" {
		t.Errorf("Metadata[terraform_mode] = %q, want managed", first.Metadata["terraform_mode"])
	}
	if _, hasModule := first.Metadata["terraform_module"]; hasModule {
		t.Error("root resource should have no terraform_module metadata")
	}
}

func TestTerraformParseNestedModules(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "terraform", "valid_with_modules.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	wantIDs := []string{
		"aws_iam_role.app",
		"module.network.aws_security_group.app",
		"module.network.module.sub.aws_subnet.private",
	}
	if len(resources) != len(wantIDs) {
		t.Fatalf("Parse() returned %d resources, want %d", len(resources), len(wantIDs))
	}
	for i, want := range wantIDs {
		if resources[i].ID != want {
			t.Errorf("resources[%d].ID = %q, want %q", i, resources[i].ID, want)
		}
	}
	if got := resources[1].Metadata["terraform_module"]; got != "module.network" {
		t.Errorf("child resource module metadata = %q, want module.network", got)
	}
	if got := resources[2].Metadata["terraform_module"]; got != "module.network.module.sub" {
		t.Errorf("grandchild resource module metadata = %q, want module.network.module.sub", got)
	}
	if resources[2].Properties["cidr_block"] != "10.0.2.0/24" {
		t.Errorf("grandchild properties = %v, want cidr_block", resources[2].Properties)
	}
}

func TestTerraformParsePlanPrefersPlannedValues(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "terraform", "valid_plan.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("Parse() returned %d resources, want 1 from planned_values", len(resources))
	}
	if resources[0].ID != "aws_s3_bucket.new" {
		t.Errorf("ID = %q, want aws_s3_bucket.new", resources[0].ID)
	}
	if resources[0].Properties["bucket"] != "new-bucket" {
		t.Errorf("Properties = %v, want after values", resources[0].Properties)
	}
}

func TestTerraformParsePlanChangesFallback(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "terraform", "valid_plan_changes.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2 from resource_changes", len(resources))
	}
	if resources[0].Properties["bucket"] != "old-bucket" {
		t.Errorf("delete change should fall back to before values, got %v", resources[0].Properties)
	}
	if got := resources[0].Metadata["terraform_actions"]; got != "delete" {
		t.Errorf("Metadata[terraform_actions] = %q, want delete", got)
	}
	if got := resources[1].Properties["bucket"]; got != "replaced-bucket-v2" {
		t.Errorf("replace change after values = %v, want replaced-bucket-v2", resources[1].Properties)
	}
}

func TestTerraformParseConfig(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "terraform", "valid_config.tf.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	wantIDs := []string{"aws_iam_role.reader", "aws_s3_bucket.logs"}
	for i, want := range wantIDs {
		if resources[i].ID != want {
			t.Errorf("resources[%d].ID = %q, want %q (deterministic order)", i, resources[i].ID, want)
		}
	}
	if resources[0].Properties["name"] != "reader-role" {
		t.Errorf("properties = %v, want name reader-role", resources[0].Properties)
	}
	if got := resources[0].Metadata["terraform_config"]; got != "true" {
		t.Errorf("Metadata[terraform_config] = %q, want true", got)
	}
}

func TestTerraformParseStateWithoutValues(t *testing.T) {
	t.Parallel()
	data := `{"format_version": "1.2", "terraform_version": "1.9.5"}`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewTerraformParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("Parse() returned %d resources, want 0", len(resources))
	}
}

func TestTerraformRejectsTrailingData(t *testing.T) {
	t.Parallel()
	data := `{"format_version": "1.2"} {"format_version": "1.2"}`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewTerraformParser(0)
	if _, err := p.Parse(path); err == nil {
		t.Error("Parse() error = nil, want trailing data error")
	}
}

func TestTerraformParseErrors(t *testing.T) {
	t.Parallel()
	p := NewTerraformParser(0)
	oversize := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(oversize, make([]byte, 64), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		maxBytes  int64
		wantErr   error
		errSubstr string
	}{
		{name: "malformed json", path: filepath.Join("testdata", "terraform", "invalid.json"), errSubstr: "invalid terraform json"},
		{name: "unknown top-level field", path: filepath.Join("testdata", "terraform", "unknown_field.json"), errSubstr: "invalid terraform json"},
		{name: "empty file", path: filepath.Join("testdata", "terraform", "empty.json"), wantErr: ErrEmptyFile},
		{name: "missing file", path: filepath.Join("testdata", "terraform", "missing.json"), errSubstr: "no such file"},
		{name: "directory", path: filepath.Join("testdata", "terraform"), wantErr: ErrIsADirectory},
		{name: "over size limit", path: oversize, maxBytes: 16, wantErr: ErrFileTooLarge},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parser := p
			if tt.maxBytes != 0 {
				parser = NewTerraformParser(tt.maxBytes)
			}
			resources, err := parser.Parse(tt.path)
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

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
