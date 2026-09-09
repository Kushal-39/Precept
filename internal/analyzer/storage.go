package analyzer

import (
	"github.com/precept/precept/internal/models"
)

// Storage rule identifiers.
const (
	RuleStoPublicBucket      = "STO-001"
	RuleStoMissingEncryption = "STO-002"
	RuleStoMissingLogging    = "STO-003"
)

var (
	ruleStoPublicBucket = rule{
		ID: RuleStoPublicBucket, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "S3 bucket allows public access",
		Remediation: "Enable all four S3 public access block settings and scope bucket policies to known principals",
	}
	ruleStoMissingEncryption = rule{
		ID: RuleStoMissingEncryption, Severity: models.SeverityHigh, BaseScore: 75,
		Description: "S3 bucket has no server-side encryption configuration",
		Remediation: "Add a server_side_encryption_configuration block enforcing SSE-S3 or SSE-KMS",
	}
	ruleStoMissingLogging = rule{
		ID: RuleStoMissingLogging, Severity: models.SeverityMedium, BaseScore: 45,
		Description: "S3 bucket has no access logging configured",
		Remediation: "Add a logging block pointing at a dedicated log bucket",
	}
)

var publicACLVals = map[string]bool{
	"public-read":        true,
	"public-read-write":  true,
	"authenticated-read": true,
}

// StorageAnalyzer detects public exposure, missing encryption, and
// missing logging on S3 resources.
type StorageAnalyzer struct{}

// NewStorageAnalyzer returns a storage analyzer.
func NewStorageAnalyzer() *StorageAnalyzer { return &StorageAnalyzer{} }

// Name identifies the analyzer in logs and diagnostics.
func (a *StorageAnalyzer) Name() string { return "storage" }

// SupportedProviders lists the providers this analyzer consumes.
func (a *StorageAnalyzer) SupportedProviders() []models.ResourceType {
	return []models.ResourceType{models.ResourceTypeTerraform}
}

// Analyze runs every storage rule against one resource.
func (a *StorageAnalyzer) Analyze(resource *models.Resource) []*models.Finding {
	switch resource.Type {
	case "aws_s3_bucket":
		return a.analyzeBucket(resource)
	case "aws_s3_bucket_public_access_block":
		return a.analyzeAccessBlock(resource)
	default:
		return nil
	}
}

func (a *StorageAnalyzer) analyzeBucket(resource *models.Resource) []*models.Finding {
	var findings []*models.Finding
	if propsBool(resource.Properties["publicly_accessible"]) || publicACLVals[propsString(resource.Properties["acl"])] {
		findings = append(findings, newFinding(ruleStoPublicBucket, resource.ID))
	}
	if _, ok := resource.Properties["server_side_encryption_configuration"]; !ok {
		findings = append(findings, newFinding(ruleStoMissingEncryption, resource.ID))
	}
	if _, ok := resource.Properties["logging"]; !ok {
		findings = append(findings, newFinding(ruleStoMissingLogging, resource.ID))
	}
	return findings
}

func (a *StorageAnalyzer) analyzeAccessBlock(resource *models.Resource) []*models.Finding {
	for _, flag := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		v, ok := resource.Properties[flag]
		if !ok {
			continue
		}
		if !propsBool(v) {
			return []*models.Finding{newFinding(ruleStoPublicBucket, resource.ID)}
		}
	}
	return nil
}

func propsBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func propsString(v any) string {
	s, _ := v.(string)
	return s
}
