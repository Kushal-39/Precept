package analyzer

import (
	"encoding/json"
	"strings"

	"github.com/precept/precept/internal/models"
	"github.com/precept/precept/internal/parser"
)

// IAM rule identifiers.
const (
	RuleIAMWildcardAdmin   = "IAM-001"
	RuleIAMWildcardRes     = "IAM-002"
	RuleIAMEscalation      = "IAM-003"
	RuleIAMPassRole        = "IAM-004"
	RuleIAMFullAdmin       = "IAM-005"
	RuleIAMTerraformPolicy = "IAM-006"
)

const adminAccessARN = "arn:aws:iam::aws:policy/AdministratorAccess"

var (
	ruleIAMWildcardAdmin = rule{
		ID: RuleIAMWildcardAdmin, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "IAM statement allows all actions with a wildcard",
		Remediation: "Replace wildcard actions with the explicit least-privilege set the workload needs",
	}
	ruleIAMWildcardRes = rule{
		ID: RuleIAMWildcardRes, Severity: models.SeverityCritical, BaseScore: 90,
		Description: "IAM statement applies to all resources with a wildcard",
		Remediation: "Scope the statement to specific resource ARNs",
	}
	ruleIAMEscalation = rule{
		ID: RuleIAMEscalation, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "IAM statement grants policy administration with AdministratorAccess, enabling privilege escalation",
		Remediation: "Remove iam:AttachRolePolicy or iam:PutRolePolicy combined with AdministratorAccess; grant scoped policy management instead",
	}
	ruleIAMPassRole = rule{
		ID: RuleIAMPassRole, Severity: models.SeverityHigh, BaseScore: 80,
		Description: "IAM statement permits iam:PassRole on all resources",
		Remediation: "Restrict iam:PassRole to specific role ARNs the workload actually assumes",
	}
	ruleIAMFullAdmin = rule{
		ID: RuleIAMFullAdmin, Severity: models.SeverityCritical, BaseScore: 92,
		Description: "IAM statement grants full iam:* on all resources",
		Remediation: "Split iam:* into the specific IAM actions the workload needs",
	}
	ruleIAMTerraformPolicy = rule{
		ID: RuleIAMTerraformPolicy, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "IAM policy embedded in Terraform grants wildcard administrative permissions",
		Remediation: "Replace wildcard permissions with least-privilege policies",
	}
)

// IAMAnalyzer detects over-permissive statements in IAM policy documents
// and in IAM policies embedded inside Terraform resources.
type IAMAnalyzer struct{}

// NewIAMAnalyzer returns an IAM analyzer.
func NewIAMAnalyzer() *IAMAnalyzer { return &IAMAnalyzer{} }

// Name identifies the analyzer in logs and diagnostics.
func (a *IAMAnalyzer) Name() string { return "iam" }

// SupportedProviders lists the providers this analyzer consumes.
func (a *IAMAnalyzer) SupportedProviders() []models.ResourceType {
	return []models.ResourceType{models.ResourceTypeIAM, models.ResourceTypeTerraform}
}

// Analyze runs every IAM rule against one resource.
func (a *IAMAnalyzer) Analyze(resource *models.Resource) []*models.Finding {
	var findings []*models.Finding
	switch resource.Provider {
	case models.ResourceTypeIAM:
		findings = a.analyzeIAMStatementResource(resource)
	case models.ResourceTypeTerraform:
		findings = a.analyzeTerraformResource(resource)
	}
	return findings
}

func (a *IAMAnalyzer) analyzeIAMStatementResource(resource *models.Resource) []*models.Finding {
	effect, _ := resource.Properties["effect"].(string)
	if effect == "Deny" {
		return nil
	}
	var findings []*models.Finding
	if hasWildcard(stringsList(resource.Properties["action"])) {
		findings = append(findings, newFinding(ruleIAMWildcardAdmin, resource.ID))
	}
	if hasWildcard(stringsList(resource.Properties["resource"])) {
		findings = append(findings, newFinding(ruleIAMWildcardRes, resource.ID))
	}
	actions := lowerAll(stringsList(resource.Properties["action"]))
	resources := stringsList(resource.Properties["resource"])
	if slicesContains(actions, "iam:attachrolepolicy") || slicesContains(actions, "iam:putrolepolicy") {
		if policyHasAdminAccess(resource.Properties) || hasWildcard(resources) {
			findings = append(findings, newFinding(ruleIAMEscalation, resource.ID))
		}
	}
	if slicesContains(actions, "iam:passrole") && hasWildcard(resources) {
		findings = append(findings, newFinding(ruleIAMPassRole, resource.ID))
	}
	if slicesContains(actions, "iam:*") && hasWildcard(resources) {
		findings = append(findings, newFinding(ruleIAMFullAdmin, resource.ID))
	}
	return findings
}

// embeddedPolicyFields are Terraform properties that carry inline IAM
// policy JSON documents.
var embeddedPolicyFields = []string{"assume_role_policy", "policy"}

func (a *IAMAnalyzer) analyzeTerraformResource(resource *models.Resource) []*models.Finding {
	typeName := resource.Type
	if typeName != "aws_iam_role" && typeName != "aws_iam_policy" &&
		typeName != "aws_iam_role_policy" && typeName != "aws_iam_user_policy" {
		return nil
	}
	var findings []*models.Finding
	for _, field := range embeddedPolicyFields {
		raw, ok := resource.Properties[field].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		statements, err := parser.ParseStatements([]byte(raw))
		if err != nil {
			continue
		}
		for _, stmt := range statements {
			if stmt.Effect == "Deny" {
				continue
			}
			if hasWildcard(stmt.Action) || hasWildcard(stmt.Resource) {
				findings = append(findings, newFinding(ruleIAMTerraformPolicy, resource.ID))
				break
			}
		}
	}
	return findings
}

func policyHasAdminAccess(props map[string]any) bool {
	if stringsList(props["resource"]) == nil {
		return false
	}
	for _, field := range []string{"condition", "principal"} {
		if data, err := json.Marshal(props[field]); err == nil && strings.Contains(string(data), adminAccessARN) {
			return true
		}
	}
	return false
}

func hasWildcard(list []string) bool {
	return slicesContains(list, "*")
}

func stringsList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case string:
		return []string{list}
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func lowerAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = strings.ToLower(s)
	}
	return out
}

func slicesContains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
