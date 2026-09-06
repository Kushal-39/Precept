package models

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSeverityValid(t *testing.T) {
	tests := []struct {
		name string
		sev  Severity
		want bool
	}{
		{"critical", SeverityCritical, true},
		{"high", SeverityHigh, true},
		{"medium", SeverityMedium, true},
		{"low", SeverityLow, true},
		{"empty", Severity(""), false},
		{"lowercase", Severity("critical"), false},
		{"unknown", Severity("EXTREME"), false},
		{"numeric string", Severity("4"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sev.Valid(); got != tt.want {
				t.Errorf("Severity(%q).Valid() = %v, want %v", tt.sev, got, tt.want)
			}
		})
	}
}

func TestNewFindingValid(t *testing.T) {
	before := time.Now()
	f, err := NewFinding("PRE-001", "aws_s3_bucket.data", "Bucket is public", "Enable block_public_acls", SeverityHigh, 85)
	if err != nil {
		t.Fatalf("NewFinding() unexpected error: %v", err)
	}
	if f.RuleID != "PRE-001" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "PRE-001")
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("Resource = %q, want %q", f.Resource, "aws_s3_bucket.data")
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, SeverityHigh)
	}
	if f.Description != "Bucket is public" {
		t.Errorf("Description = %q, want %q", f.Description, "Bucket is public")
	}
	if f.Remediation != "Enable block_public_acls" {
		t.Errorf("Remediation = %q, want %q", f.Remediation, "Enable block_public_acls")
	}
	if f.RiskScore != 85 {
		t.Errorf("RiskScore = %d, want 85", f.RiskScore)
	}
	if f.Timestamp.Before(before) {
		t.Errorf("Timestamp %v is before test start %v", f.Timestamp, before)
	}
}

func TestNewFindingValidation(t *testing.T) {
	tests := []struct {
		name        string
		ruleID      string
		resource    string
		description string
		remediation string
		severity    Severity
		score       int
		wantErr     error
	}{
		{
			name:        "valid boundary zero score",
			ruleID:      "PRE-002",
			resource:    "k8s.pod.default",
			description: "runs as root",
			severity:    SeverityMedium,
			score:       0,
		},
		{
			name:        "valid boundary max score",
			ruleID:      "PRE-003",
			resource:    "aws_iam_role.admin",
			description: "wildcard actions",
			severity:    SeverityCritical,
			score:       100,
		},
		{
			name:        "empty ruleID",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    SeverityHigh,
			score:       85,
			wantErr:     ErrEmptyField,
		},
		{
			name:        "empty resource",
			ruleID:      "PRE-001",
			description: "Bucket is public",
			severity:    SeverityHigh,
			score:       85,
			wantErr:     ErrEmptyField,
		},
		{
			name:     "empty description",
			ruleID:   "PRE-001",
			resource: "aws_s3_bucket.data",
			severity: SeverityHigh,
			score:    85,
			wantErr:  ErrEmptyField,
		},
		{
			name:        "empty remediation allowed",
			ruleID:      "PRE-004",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    SeverityLow,
			score:       10,
		},
		{
			name:        "score above 100",
			ruleID:      "PRE-001",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    SeverityHigh,
			score:       101,
			wantErr:     ErrScoreOutOfRange,
		},
		{
			name:        "negative score",
			ruleID:      "PRE-001",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    SeverityHigh,
			score:       -1,
			wantErr:     ErrScoreOutOfRange,
		},
		{
			name:        "invalid severity lowercase",
			ruleID:      "PRE-001",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    Severity("high"),
			score:       85,
			wantErr:     ErrInvalidSeverity,
		},
		{
			name:        "invalid severity empty",
			ruleID:      "PRE-001",
			resource:    "aws_s3_bucket.data",
			description: "Bucket is public",
			severity:    Severity(""),
			score:       85,
			wantErr:     ErrInvalidSeverity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.ruleID, tt.resource, tt.description, tt.remediation, tt.severity, tt.score)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("NewFinding() error = nil, want %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewFinding() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFinding() unexpected error: %v", err)
			}
			if f.RiskScore != tt.score {
				t.Errorf("RiskScore = %d, want %d", f.RiskScore, tt.score)
			}
		})
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	f, err := NewFinding("PRE-005", "k8s.secret.default", "Secret not encrypted", "Enable encryption", SeverityCritical, 95)
	if err != nil {
		t.Fatalf("NewFinding() unexpected error: %v", err)
	}
	f.ID = "f-1234"

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var got Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if got.ID != f.ID || got.RuleID != f.RuleID || got.Resource != f.Resource ||
		got.Severity != f.Severity || got.Description != f.Description ||
		got.Remediation != f.Remediation || got.RiskScore != f.RiskScore {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, f)
	}
	if !got.Timestamp.Equal(f.Timestamp) {
		t.Errorf("Timestamp: got %v, want %v", got.Timestamp, f.Timestamp)
	}
}

func TestFindingJSONFieldNames(t *testing.T) {
	f, err := NewFinding("PRE-006", "aws_sg.open", "Port 22 open to world", "Restrict CIDR", SeverityHigh, 75)
	if err != nil {
		t.Fatalf("NewFinding() unexpected error: %v", err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	wantKeys := []string{"id", "rule_id", "resource", "severity", "description", "remediation", "risk_score", "timestamp"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON key %q in %s", key, data)
		}
	}
}

func TestFindingUnmarshalInvalidSeverity(t *testing.T) {
	input := `{"rule_id":"PRE-007","resource":"r","severity":"SEVERE","description":"d","risk_score":50,"timestamp":"2026-01-01T00:00:00Z"}`
	var f Finding
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if f.Severity.Valid() {
		t.Errorf("expected unrecognised severity to survive unmarshal, got valid %q", f.Severity)
	}
	if _, err := NewFinding(f.RuleID, f.Resource, f.Description, f.Remediation, f.Severity, f.RiskScore); !errors.Is(err, ErrInvalidSeverity) {
		t.Errorf("NewFinding() on unmarshalled data error = %v, want ErrInvalidSeverity", err)
	}
}
