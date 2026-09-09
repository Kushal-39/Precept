package output

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

// TestMain disables color once, serially, so parallel tests never race
// on the package-global NoColor flag.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func mkFinding(t *testing.T, ruleID, resource, description string, severity models.Severity, score int) *models.Finding {
	t.Helper()
	f, err := models.NewFinding(ruleID, resource, description, "Fix it", severity, score)
	if err != nil {
		t.Fatalf("NewFinding error: %v", err)
	}
	return &f
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()
	findings := []*models.Finding{
		mkFinding(t, "IAM-001", "aws_s3_bucket.data", "wildcard admin", models.SeverityCritical, 95),
	}
	data, err := FormatJSON(findings)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}
	var parsed []models.Finding
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}
	if len(parsed) != 1 || parsed[0].RuleID != "IAM-001" {
		t.Errorf("parsed = %+v, want one IAM-001 finding", parsed)
	}
	if !strings.Contains(data, `"rule_id": "IAM-001"`) || !strings.Contains(data, `"risk_score": 95`) {
		t.Errorf("output missing expected fields:\n%s", data)
	}
}

func TestFormatJSONEmpty(t *testing.T) {
	t.Parallel()
	for _, findings := range [][]*models.Finding{nil, {}} {
		data, err := FormatJSON(findings)
		if err != nil {
			t.Fatalf("FormatJSON error: %v", err)
		}
		if strings.TrimSpace(data) != "[]" {
			t.Errorf("FormatJSON() = %q, want []", data)
		}
	}
}

func TestFormatTableLayout(t *testing.T) {
	t.Parallel()
	findings := []*models.Finding{
		mkFinding(t, "NET-001", "aws_security_group.open", "SSH port 22 is reachable from the public internet (ingress rule 0 (22))", models.SeverityCritical, 95),
		mkFinding(t, "STO-003", "aws_s3_bucket.data", "S3 bucket has no access logging configured", models.SeverityMedium, 45),
	}
	table := FormatTable(findings, 70)
	for _, want := range []string{"SEVERITY", "RULE", "RESOURCE", "DESCRIPTION", "SCORE"} {
		if !strings.Contains(table, want) {
			t.Errorf("table missing header %q:\n%s", want, table)
		}
	}
	if !strings.Contains(table, "NET-001") || !strings.Contains(table, "aws_security_group.open") {
		t.Errorf("table missing finding row:\n%s", table)
	}
	lines := strings.Split(strings.TrimSpace(table), "\n")
	if len(lines) != 5 {
		t.Errorf("table has %d lines, want 5 (header, rule, 2 findings, summary)", len(lines))
	}
}

func TestFormatTableSummary(t *testing.T) {
	t.Parallel()
	findings := []*models.Finding{
		mkFinding(t, "IAM-001", "res", "d", models.SeverityCritical, 95),
	}
	if got := FormatTable(findings, 80); !strings.Contains(got, "Found 1 finding. Max risk score: 95/100. Scan FAILED.") {
		t.Errorf("summary = %q, want FAILED line", got)
	}
	if got := FormatTable(findings, 100); !strings.Contains(got, "Found 1 finding. Max risk score: 95/100. Scan PASSED.") {
		t.Errorf("summary = %q, want PASSED line", got)
	}
	if got := FormatTable(findings, 90); !strings.Contains(got, "Scan FAILED.") {
		t.Errorf("summary at boundary = %q, want FAILED (max >= threshold)", got)
	}
}

func TestFormatTableEmpty(t *testing.T) {
	t.Parallel()
	table := FormatTable(nil, 70)
	if !strings.Contains(table, "Found 0 findings. Max risk score: 0/100. Scan PASSED.") {
		t.Errorf("empty summary = %q", table)
	}
	if !strings.Contains(table, "No findings") {
		t.Errorf("empty table missing placeholder row:\n%s", table)
	}
}

func TestFormatTableTruncation(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 80)
	findings := []*models.Finding{
		mkFinding(t, "T-001", long, long, models.SeverityLow, 10),
	}
	table := FormatTable(findings, 70)
	if strings.Count(table, long) != 0 {
		t.Error("long values not truncated")
	}
	if !strings.Contains(table, "...") {
		t.Errorf("truncation marker missing:\n%s", table)
	}
}

func TestDescriptionWidthConstants(t *testing.T) {
	t.Parallel()
	if colSeverity < len("CRITICAL") || colRule < len("NET-001") || colScore < len("SCORE") || colDescription < 11 {
		t.Error("column widths too narrow for content")
	}
}
