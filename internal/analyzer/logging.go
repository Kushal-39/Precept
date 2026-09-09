package analyzer

import (
	"github.com/precept/precept/internal/models"
)

// Logging rule identifiers.
const (
	RuleLogMissingTrail = "LOG-001"
	RuleLogShortRetain  = "LOG-002"
	RuleLogMissingKMS   = "LOG-003"
)

const minRetentionDays = 365

var (
	ruleLogMissingTrail = rule{
		ID: RuleLogMissingTrail, Severity: models.SeverityHigh, BaseScore: 75,
		Description: "No CloudTrail trail is defined anywhere in the scanned infrastructure",
		Remediation: "Add an aws_cloudtrail resource with multi-region logging and log file validation",
	}
	ruleLogShortRetain = rule{
		ID: RuleLogShortRetain, Severity: models.SeverityMedium, BaseScore: 45,
		Description: "CloudWatch log group retention is shorter than 365 days",
		Remediation: "Set retention_in_days to at least 365 for audit-relevant log groups",
	}
	ruleLogMissingKMS = rule{
		ID: RuleLogMissingKMS, Severity: models.SeverityLow, BaseScore: 20,
		Description: "Log resource has no KMS encryption configured",
		Remediation: "Set kms_key_id to a customer-managed KMS key",
	}
)

// LoggingAnalyzer checks log retention, KMS encryption, and the
// presence of CloudTrail across the whole scan. The trail-existence
// check is a corpus-level rule, so this analyzer implements BatchAnalyzer.
type LoggingAnalyzer struct{}

// NewLoggingAnalyzer returns a logging analyzer.
func NewLoggingAnalyzer() *LoggingAnalyzer { return &LoggingAnalyzer{} }

// Name identifies the analyzer in logs and diagnostics.
func (a *LoggingAnalyzer) Name() string { return "logging" }

// SupportedProviders lists the providers this analyzer consumes.
func (a *LoggingAnalyzer) SupportedProviders() []models.ResourceType {
	return []models.ResourceType{models.ResourceTypeTerraform}
}

// Analyze runs the per-resource logging rules against one resource.
func (a *LoggingAnalyzer) Analyze(resource *models.Resource) []*models.Finding {
	switch resource.Type {
	case "aws_cloudwatch_log_group":
		return a.analyzeLogGroup(resource)
	case "aws_cloudtrail":
		return a.analyzeTrail(resource)
	default:
		return nil
	}
}

// AnalyzeBatch implements BatchAnalyzer: it reports a HIGH finding when
// no aws_cloudtrail resource exists anywhere in the scan.
func (a *LoggingAnalyzer) AnalyzeBatch(resources []*models.Resource) []*models.Finding {
	if len(resources) == 0 {
		return nil
	}
	for _, r := range resources {
		if r.Type == "aws_cloudtrail" {
			return nil
		}
	}
	return []*models.Finding{newFinding(ruleLogMissingTrail, "corpus")}
}

func (a *LoggingAnalyzer) analyzeLogGroup(resource *models.Resource) []*models.Finding {
	var findings []*models.Finding
	if days, ok := resource.Properties["retention_in_days"].(float64); ok && days < minRetentionDays {
		findings = append(findings, newFinding(ruleLogShortRetain, resource.ID))
	}
	if _, ok := resource.Properties["kms_key_id"]; !ok {
		findings = append(findings, newFinding(ruleLogMissingKMS, resource.ID))
	}
	return findings
}

func (a *LoggingAnalyzer) analyzeTrail(resource *models.Resource) []*models.Finding {
	if _, ok := resource.Properties["kms_key_id"]; !ok {
		return []*models.Finding{newFinding(ruleLogMissingKMS, resource.ID)}
	}
	return nil
}
