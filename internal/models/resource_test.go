package models

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestResourceTypeValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		typ  ResourceType
		want bool
	}{
		{"terraform", ResourceTypeTerraform, true},
		{"kubernetes", ResourceTypeKubernetes, true},
		{"iam", ResourceTypeIAM, true},
		{"cloudtrail", ResourceTypeCloudTrail, true},
		{"empty", ResourceType(""), false},
		{"unknown", ResourceType("ansible"), false},
		{"uppercase", ResourceType("Terraform"), false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.typ.Valid(); got != tt.want {
				t.Errorf("ResourceType(%q).Valid() = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

func TestNewResourceValid(t *testing.T) {
	t.Parallel()
	props := map[string]any{"bucket": "precept-data", "acl": "private"}
	r, err := NewResource("aws_s3_bucket.data", "aws_s3_bucket", "data", "terraform", props)
	if err != nil {
		t.Fatalf("NewResource() unexpected error: %v", err)
	}
	if r.ID != "aws_s3_bucket.data" {
		t.Errorf("ID = %q, want %q", r.ID, "aws_s3_bucket.data")
	}
	if r.Type != "aws_s3_bucket" {
		t.Errorf("Type = %q, want %q", r.Type, "aws_s3_bucket")
	}
	if r.Name != "data" {
		t.Errorf("Name = %q, want %q", r.Name, "data")
	}
	if r.Provider != ResourceTypeTerraform {
		t.Errorf("Provider = %q, want %q", r.Provider, ResourceTypeTerraform)
	}
	if r.Properties["bucket"] != "precept-data" {
		t.Errorf("Properties[bucket] = %v, want %q", r.Properties["bucket"], "precept-data")
	}
	if r.Metadata == nil {
		t.Error("Metadata = nil, want initialised empty map")
	}
}

func TestNewResourceTrimsWhitespace(t *testing.T) {
	t.Parallel()
	r, err := NewResource("  aws_s3_bucket.data  ", " aws_s3_bucket ", " data ", " terraform ", nil)
	if err != nil {
		t.Fatalf("NewResource() unexpected error: %v", err)
	}
	if r.ID != "aws_s3_bucket.data" || r.Type != "aws_s3_bucket" || r.Name != "data" {
		t.Errorf("fields not trimmed: id=%q type=%q name=%q", r.ID, r.Type, r.Name)
	}
}

func TestNewResourceCopiesProperties(t *testing.T) {
	t.Parallel()
	props := map[string]any{"acl": "private"}
	r, err := NewResource("aws_s3_bucket.data", "aws_s3_bucket", "data", "terraform", props)
	if err != nil {
		t.Fatalf("NewResource() unexpected error: %v", err)
	}
	props["acl"] = "public-read"
	if r.Properties["acl"] != "private" {
		t.Errorf("Properties alias input map: got %v, want %q", r.Properties["acl"], "private")
	}
}

func TestNewResourceNilProperties(t *testing.T) {
	t.Parallel()
	r, err := NewResource("k8s/pod", "Pod", "pod", "kubernetes", nil)
	if err != nil {
		t.Fatalf("NewResource() unexpected error: %v", err)
	}
	if r.Properties == nil {
		t.Error("Properties = nil, want empty map")
	}
	if len(r.Properties) != 0 {
		t.Errorf("Properties = %v, want empty", r.Properties)
	}
}

func TestNewResourceValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		id           string
		resourceType string
		resourceNam  string
		provider     string
		wantErr      error
	}{
		{name: "valid kubernetes", id: "Pod/api", resourceType: "Pod", resourceNam: "api", provider: "kubernetes"},
		{name: "valid iam", id: "policy.json#0", resourceType: "Statement", resourceNam: "AllowObjectRead", provider: "iam"},
		{name: "valid cloudtrail", id: "evt-1", resourceType: "CreateBucket", resourceNam: "CreateBucket", provider: "cloudtrail"},
		{name: "empty id", id: "", resourceType: "Pod", resourceNam: "api", provider: "kubernetes", wantErr: ErrEmptyField},
		{name: "whitespace id", id: "   ", resourceType: "Pod", resourceNam: "api", provider: "kubernetes", wantErr: ErrEmptyField},
		{name: "empty type", id: "Pod/api", resourceType: "", resourceNam: "api", provider: "kubernetes", wantErr: ErrEmptyField},
		{name: "empty name", id: "Pod/api", resourceType: "Pod", resourceNam: "", provider: "kubernetes", wantErr: ErrEmptyField},
		{name: "empty provider", id: "Pod/api", resourceType: "Pod", resourceNam: "api", provider: "", wantErr: ErrEmptyField},
		{name: "unknown provider", id: "Pod/api", resourceType: "Pod", resourceNam: "api", provider: "ansible", wantErr: ErrInvalidProvider},
		{name: "case sensitive provider", id: "Pod/api", resourceType: "Pod", resourceNam: "api", provider: "Kubernetes", wantErr: ErrInvalidProvider},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := NewResource(tt.id, tt.resourceType, tt.resourceNam, tt.provider, nil)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("NewResource() error = nil, want %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewResource() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewResource() unexpected error: %v", err)
			}
			if r.Provider != ResourceType(tt.provider) {
				t.Errorf("Provider = %q, want %q", r.Provider, tt.provider)
			}
		})
	}
}

func TestResourceJSONRoundTrip(t *testing.T) {
	t.Parallel()
	want, err := NewResource("aws_s3_bucket.data", "aws_s3_bucket", "data", "terraform",
		map[string]any{"bucket": "precept-data", "versioning": []any{map[string]any{"enabled": true}}})
	if err != nil {
		t.Fatalf("NewResource() unexpected error: %v", err)
	}
	want.Metadata["file"] = "testdata/terraform/valid.json"
	want.Metadata["terraform_provider"] = "registry.terraform.io/hashicorp/aws"

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	var got Resource
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if got.ID != want.ID || got.Type != want.Type || got.Name != want.Name || got.Provider != want.Provider {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Properties["bucket"] != "precept-data" {
		t.Errorf("Properties[bucket] = %v, want %q", got.Properties["bucket"], "precept-data")
	}
	if got.Metadata["file"] != want.Metadata["file"] {
		t.Errorf("Metadata[file] = %q, want %q", got.Metadata["file"], want.Metadata["file"])
	}
}
