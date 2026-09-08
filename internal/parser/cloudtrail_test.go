package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestCloudTrailParseRecords(t *testing.T) {
	t.Parallel()
	p := NewCloudTrailParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "cloudtrail", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	first := resources[0]
	if first.ID != "a1111111-2222-3333-4444-555555555555" {
		t.Errorf("ID = %q, want event id", first.ID)
	}
	if first.Provider != models.ResourceTypeCloudTrail {
		t.Errorf("Provider = %q, want %q", first.Provider, models.ResourceTypeCloudTrail)
	}
	if first.Type != "CreateBucket" || first.Name != "CreateBucket" {
		t.Errorf("Type/Name = %q/%q, want CreateBucket", first.Type, first.Name)
	}
	if got, ok := first.Properties["event_source"].(string); !ok || got != "s3.amazonaws.com" {
		t.Errorf("Properties[event_source] = %v, want s3.amazonaws.com", first.Properties["event_source"])
	}
	if _, ok := first.Properties["user_identity"]; !ok {
		t.Error("Properties[user_identity] missing")
	}
	if _, ok := first.Properties["request_parameters"]; !ok {
		t.Error("Properties[request_parameters] missing")
	}
	if got := first.Metadata["record_index"]; got != "0" {
		t.Errorf("Metadata[record_index] = %q, want 0", got)
	}
	second := resources[1]
	if got, ok := second.Properties["error_code"].(string); !ok || got != "AccessDenied" {
		t.Errorf("Properties[error_code] = %v, want AccessDenied", second.Properties["error_code"])
	}
	if _, ok := second.Properties["user_identity"]; ok {
		t.Error("Properties[user_identity] should be absent for record without it")
	}
}

func TestCloudTrailParseSingleEvent(t *testing.T) {
	t.Parallel()
	p := NewCloudTrailParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "cloudtrail", "single_event.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("Parse() returned %d resources, want 1", len(resources))
	}
	if resources[0].Type != "AssumeRole" {
		t.Errorf("Type = %q, want AssumeRole", resources[0].Type)
	}
}

func TestCloudTrailParseArray(t *testing.T) {
	t.Parallel()
	data := `[
		{"eventVersion": "1.08", "eventName": "CreateUser", "eventSource": "iam.amazonaws.com"},
		{"eventVersion": "1.08", "eventName": "DeleteUser", "eventSource": "iam.amazonaws.com"}
	]`
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewCloudTrailParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	// Records without eventID synthesise deterministic unique IDs.
	if got := resources[1].ID; got != "iam.amazonaws.com/DeleteUser#1" {
		t.Errorf("ID = %q, want iam.amazonaws.com/DeleteUser#1", got)
	}
}

func TestCloudTrailExtraFieldsTolerated(t *testing.T) {
	t.Parallel()
	data := `{"Records": [{"eventVersion": "1.08", "eventName": "RunInstances", "eventSource": "ec2.amazonaws.com", "someFutureServiceField": {"nested": true}}]}`
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewCloudTrailParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v (service-specific fields must be tolerated)", err)
	}
	if len(resources) != 1 {
		t.Fatalf("Parse() returned %d resources, want 1", len(resources))
	}
}

func TestCloudTrailParseErrors(t *testing.T) {
	t.Parallel()
	p := NewCloudTrailParser(0)
	write := func(t *testing.T, data string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "events.json")
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
		{name: "malformed json", path: filepath.Join("testdata", "cloudtrail", "invalid.json"), errSubstr: "invalid cloudtrail"},
		{name: "empty file", path: filepath.Join("testdata", "cloudtrail", "empty.json"), wantErr: ErrEmptyFile},
		{name: "empty records", path: write(t, `{"Records": []}`), wantErr: ErrMissingField},
		{name: "missing event name", path: write(t, `{"eventVersion": "1.08", "eventSource": "s3.amazonaws.com"}`), errSubstr: "eventName"},
		{name: "missing event source", path: write(t, `{"eventVersion": "1.08", "eventName": "GetBucket"}`), errSubstr: "eventSource"},
		{name: "empty object", path: write(t, `{}`), errSubstr: "eventName"},
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
