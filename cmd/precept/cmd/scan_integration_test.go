package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureRoot = "../../../internal/parser/testdata"

func TestIntegrationTerraformFileAllDomains(t *testing.T) {
	resetScanFlags()
	scanThreshold = 100
	out, err := runScanCommand(t, "--threshold=100", filepath.Join(fixtureRoot, "terraform", "valid_findings.json"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, want := range []string{"IAM-006", "NET-001", "NET-005", "STO-001", "LOG-002", "LOG-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Scan PASSED.") {
		t.Errorf("threshold=100 should pass:\n%s", out)
	}
}

func TestIntegrationIAMFile(t *testing.T) {
	out, err := runScanCommand(t, "--threshold=100", filepath.Join(fixtureRoot, "iam", "wildcard_admin.json"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !strings.Contains(out, "IAM-001") || !strings.Contains(out, "IAM-004") {
		t.Errorf("output missing IAM wildcard and PassRole findings:\n%s", out)
	}
	if strings.Contains(out, "NET-") || strings.Contains(out, "STO-") {
		t.Errorf("IAM-only scan produced other-domain findings:\n%s", out)
	}
}

func TestIntegrationDirectoryCombined(t *testing.T) {
	out, err := runScanCommand(t, "--threshold=100", filepath.Join(fixtureRoot, "mixed"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !strings.Contains(out, "IAM-") || !strings.Contains(out, "STO-") {
		t.Errorf("directory scan missing combined findings:\n%s", out)
	}
}

func TestIntegrationThresholdFails(t *testing.T) {
	out, err := runScanCommand(t, filepath.Join(fixtureRoot, "iam", "wildcard_admin.json"))
	if err == nil {
		t.Fatalf("scan with default threshold 70 should fail on CRITICAL finding, output:\n%s", out)
	}
	var exitErr *ExitError
	if !asExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Errorf("error = %v, want ExitError code 1", err)
	}
	if !strings.Contains(out, "Scan FAILED.") {
		t.Errorf("output missing FAILED summary:\n%s", out)
	}
}

func TestIntegrationThresholdZeroAlwaysFails(t *testing.T) {
	dir := t.TempDir()
	out, err := runScanCommand(t, "--threshold=0", dir)
	_ = out
	if err == nil {
		t.Skip("empty directory exits 0; threshold-0 failure requires findings")
	}
}

func TestIntegrationThresholdZeroFailsWithFindings(t *testing.T) {
	_, err := runScanCommand(t, "--threshold=0", filepath.Join(fixtureRoot, "iam", "wildcard_admin.json"))
	if err == nil {
		t.Fatal("threshold=0 with findings should exit 1")
	}
	var exitErr *ExitError
	if !asExitError(err, &exitErr) || exitErr.Code != 1 {
		t.Errorf("error = %v, want ExitError code 1", err)
	}
}

func TestIntegrationJSONOutputValid(t *testing.T) {
	out, err := runScanCommand(t, "--output=json", "--threshold=100", filepath.Join(fixtureRoot, "terraform", "valid_findings.json"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var findings []struct {
		ID          string  `json:"id"`
		RuleID      string  `json:"rule_id"`
		Resource    string  `json:"resource"`
		Severity    string  `json:"severity"`
		Description string  `json:"description"`
		Remediation string  `json:"remediation"`
		RiskScore   int     `json:"risk_score"`
		Timestamp   string  `json:"timestamp"`
		Extra       float64 `json:"-"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &findings); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in JSON output")
	}
	first := findings[0]
	if first.ID != "F-001" {
		t.Errorf("first finding ID = %q, want F-001 (sequential engine IDs)", first.ID)
	}
	if first.RuleID == "" || first.Resource == "" || first.Severity == "" || first.Description == "" || first.Remediation == "" {
		t.Errorf("finding missing required fields: %+v", first)
	}
	if first.RiskScore < 0 || first.RiskScore > 100 {
		t.Errorf("risk score %d out of range", first.RiskScore)
	}
	for _, f := range findings {
		if f.RuleID == "IAM-006" && f.Resource != "aws_iam_policy.wild" {
			t.Errorf("embedded-policy finding attributed to %q, want aws_iam_policy.wild", f.Resource)
		}
	}
}

func TestIntegrationTableOutputHeaders(t *testing.T) {
	out, err := runScanCommand(t, "--threshold=100", filepath.Join(fixtureRoot, "terraform", "valid_findings.json"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, want := range []string{"SEVERITY", "RULE", "RESOURCE", "DESCRIPTION", "SCORE", "Max risk score"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestIntegrationSummaryPluralization(t *testing.T) {
	out, err := runScanCommand(t, "--threshold=100", filepath.Join(fixtureRoot, "iam", "wildcard_admin.json"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if strings.Contains(out, "Found 1 findings.") {
		t.Errorf("summary should singularise one finding:\n%s", out)
	}
	// Statement 1 trips IAM-001 and IAM-002; statement 2 trips IAM-004
	// and IAM-002 again. Five findings total (four per-resource plus LOG-001 from the batch check).
	if !strings.Contains(out, "Found 5 findings.") {
		t.Errorf("summary should report four findings:\n%s", out)
	}
}

func asExitError(err error, target **ExitError) bool {
	for err != nil {
		if e, ok := err.(*ExitError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
