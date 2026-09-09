package analyzer

import (
	"encoding/json"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestClampScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity models.Severity
		base     int
		want     int
	}{
		{"critical at band floor", models.SeverityCritical, 80, 90},
		{"critical in band", models.SeverityCritical, 95, 95},
		{"critical above band", models.SeverityCritical, 105, 100},
		{"high at band floor", models.SeverityHigh, 50, 70},
		{"high in band", models.SeverityHigh, 80, 80},
		{"high above band", models.SeverityHigh, 95, 89},
		{"medium in band", models.SeverityMedium, 50, 50},
		{"medium below band", models.SeverityMedium, 10, 40},
		{"low in band", models.SeverityLow, 20, 20},
		{"low below band", models.SeverityLow, 0, 1},
		{"unknown severity passthrough", models.Severity("BANANA"), 55, 55},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := clampScore(tt.severity, tt.base); got != tt.want {
				t.Errorf("clampScore(%q, %d) = %d, want %d", tt.severity, tt.base, got, tt.want)
			}
		})
	}
}

func TestNewFinding(t *testing.T) {
	t.Parallel()
	r := rule{
		ID:          "TEST-001",
		Severity:    models.SeverityHigh,
		BaseScore:   80,
		Description: "Static description",
		Remediation: "Fix it",
	}
	f := newFinding(r, "res-1")
	if f == nil {
		t.Fatal("newFinding() = nil, want finding")
	}
	if f.RuleID != "TEST-001" || f.Resource != "res-1" {
		t.Errorf("finding = %+v, want rule TEST-001 on res-1", f)
	}
	if f.Severity != models.SeverityHigh || f.RiskScore != 80 {
		t.Errorf("severity/score = %q/%d, want HIGH/80", f.Severity, f.RiskScore)
	}
	if f.Description != "Static description" {
		t.Errorf("Description = %q, want static text", f.Description)
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp not set")
	}

	formatted := newFinding(rule{
		ID:          "TEST-002",
		Severity:    models.SeverityCritical,
		BaseScore:   95,
		Description: "Port %d exposed to %s",
		Remediation: "Fix it",
	}, "res-2", 22, "0.0.0.0/0")
	if formatted == nil {
		t.Fatal("newFinding() = nil, want finding")
	}
	if formatted.Description != "Port 22 exposed to 0.0.0.0/0" {
		t.Errorf("Description = %q, want formatted text", formatted.Description)
	}
}

func TestNewFindingDropsInvalidRule(t *testing.T) {
	t.Parallel()
	bad := rule{ID: "", Severity: models.SeverityHigh, BaseScore: 80, Description: "x", Remediation: "y"}
	if f := newFinding(bad, "res-1"); f != nil {
		t.Errorf("newFinding() with invalid rule = %+v, want nil", f)
	}
}

func TestMaxScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scores   []int
		wantHigh int
	}{
		{name: "empty", scores: nil, wantHigh: 0},
		{name: "single", scores: []int{42}, wantHigh: 42},
		{name: "multiple", scores: []int{10, 95, 70}, wantHigh: 95},
		{name: "all zero scores would still floor", scores: []int{-5}, wantHigh: 0},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := make([]*models.Finding, 0, len(tt.scores))
			for _, s := range tt.scores {
				f, err := models.NewFinding("R", "res", "d", "r", models.SeverityLow, 1)
				if err != nil {
					t.Fatalf("NewFinding error: %v", err)
				}
				f.RiskScore = s
				findings = append(findings, &f)
			}
			if got := MaxScore(findings); got != tt.wantHigh {
				t.Errorf("MaxScore() = %d, want %d", got, tt.wantHigh)
			}
		})
	}
}

func TestSortFindings(t *testing.T) {
	t.Parallel()
	mk := func(score int, ruleID, resource string) *models.Finding {
		f, err := models.NewFinding(ruleID, resource, "d", "r", models.SeverityLow, score)
		if err != nil {
			t.Fatalf("NewFinding error: %v", err)
		}
		return &f
	}
	findings := []*models.Finding{
		mk(50, "B-001", "res-2"),
		mk(95, "A-002", "res-1"),
		mk(95, "A-001", "res-9"),
		mk(95, "A-001", "res-1"),
	}
	SortFindings(findings)
	want := []struct {
		ruleID   string
		resource string
	}{{"A-001", "res-1"}, {"A-001", "res-9"}, {"A-002", "res-1"}, {"B-001", "res-2"}}
	for i, w := range want {
		if findings[i].RuleID != w.ruleID || findings[i].Resource != w.resource {
			t.Errorf("findings[%d] = %s/%s, want %s/%s", i, findings[i].RuleID, findings[i].Resource, w.ruleID, w.resource)
		}
	}
	if findings[0].RiskScore != 95 || findings[3].RiskScore != 50 {
		t.Errorf("scores not ordered descending: %v", findings)
	}
}

func TestFindingJSONShape(t *testing.T) {
	t.Parallel()
	f := newFinding(rule{
		ID:          "IAM-001",
		Severity:    models.SeverityCritical,
		BaseScore:   95,
		Description: "d",
		Remediation: "r",
	}, "aws_s3_bucket.data")
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	for _, key := range []string{"id", "rule_id", "resource", "severity", "description", "remediation", "risk_score", "timestamp"} {
		if !containsKey(string(data), key) {
			t.Errorf("JSON output missing key %q: %s", key, data)
		}
	}
}

func containsKey(data, key string) bool {
	needle := `"` + key + `"`
	for i := 0; i+len(needle) <= len(data); i++ {
		if data[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
