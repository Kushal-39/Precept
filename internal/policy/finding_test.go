package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestToFinding(t *testing.T) {
	tests := []struct {
		name      string
		finding   *PolicyFinding
		wantRule  string
		wantScore int
		wantErr   bool
	}{
		{
			name:      "valid critical",
			finding:   &PolicyFinding{RuleID: "IAM-001", Severity: "CRITICAL", Score: 95, Resource: "r", Description: "d", Remediation: "m"},
			wantRule:  "IAM-001",
			wantScore: 95,
		},
		{
			name:    "nil finding",
			finding: nil,
			wantErr: true,
		},
		{
			name:    "invalid severity",
			finding: &PolicyFinding{RuleID: "X", Severity: "BOGUS", Score: 10, Resource: "r", Description: "d"},
			wantErr: true,
		},
		{
			name:    "empty rule id",
			finding: &PolicyFinding{Severity: "LOW", Score: 10, Resource: "r", Description: "d"},
			wantErr: true,
		},
		{
			name:    "score out of range",
			finding: &PolicyFinding{RuleID: "X", Severity: "LOW", Score: 101, Resource: "r", Description: "d"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := tt.finding.ToFinding()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.RuleID != tt.wantRule || f.RiskScore != tt.wantScore {
				t.Errorf("got %s/%d, want %s/%d", f.RuleID, f.RiskScore, tt.wantRule, tt.wantScore)
			}
		})
	}
}

func TestToFindingsRejectsInvalid(t *testing.T) {
	pfs := []*PolicyFinding{
		{RuleID: "IAM-001", Severity: "CRITICAL", Score: 95, Resource: "r", Description: "d"},
		{RuleID: "BAD", Severity: "NOPE", Score: 1, Resource: "r", Description: "d"},
	}
	if _, err := ToFindings(pfs); err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if _, err := ToFindings(nil); err != nil {
		t.Fatalf("nil slice should convert cleanly: %v", err)
	}
	if _, err := ToFindings([]*PolicyFinding{nil}); err == nil {
		t.Fatal("expected error for nil element")
	}
	got, err := ToFindings([]*PolicyFinding{
		{RuleID: "LOG-001", Severity: "HIGH", Score: 75, Resource: "corpus", Description: "d", Remediation: "m"},
	})
	if err != nil {
		t.Fatalf("valid conversion: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "LOG-001" || got[0].Resource != "corpus" {
		t.Fatalf("unexpected conversion result: %+v", got)
	}
}

func TestRuleIDConstants(t *testing.T) {
	if RuleIAMWildcardAdmin != "IAM-001" || RuleNetPublicSSH != "NET-001" ||
		RuleStoPublicBucket != "STO-001" || RuleLogMissingTrail != "LOG-001" {
		t.Error("rule ID constants drifted from policy values")
	}
	if QueryDeny != "data."+PolicyPackage+".deny" {
		t.Errorf("query %q does not match package %q", QueryDeny, PolicyPackage)
	}
	var _ = models.SeverityCritical
}

func writePolicy(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const goodPolicy = `package precept.authz

deny contains {"rule_id": "T-001", "severity": "LOW", "score": 10, "resource": input.id, "description": "d", "remediation": "m"} if {
	input.provider == "terraform"
}
`
