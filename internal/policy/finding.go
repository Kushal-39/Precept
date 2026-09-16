// Package policy evaluates OPA/Rego policies against normalised
// resources and converts violations into findings.
package policy

import (
	"fmt"

	"github.com/precept/precept/internal/models"
)

// Policy package and query constants.
const (
	PolicyPackage = "precept.authz"
	QueryDeny     = "data.precept.authz.deny"
)

// Rule identifiers emitted by the Rego policies.
const (
	RuleIAMWildcardAdmin   = "IAM-001"
	RuleIAMWildcardRes     = "IAM-002"
	RuleIAMEscalation      = "IAM-003"
	RuleIAMPassRole        = "IAM-004"
	RuleIAMFullAdmin       = "IAM-005"
	RuleIAMTerraformPolicy = "IAM-006"
	RuleNetPublicSSH       = "NET-001"
	RuleNetPublicRDP       = "NET-002"
	RuleNetPublicDB        = "NET-003"
	RuleNetPublicHTTP      = "NET-004"
	RuleNetPublicSubnet    = "NET-005"
	RuleStoPublicBucket    = "STO-001"
	RuleStoMissingEncrypt  = "STO-002"
	RuleStoMissingLogging  = "STO-003"
	RuleLogMissingTrail    = "LOG-001"
	RuleLogShortRetain     = "LOG-002"
	RuleLogMissingKMS      = "LOG-003"
)

// PolicyFinding is one policy violation returned by Rego evaluation.
type PolicyFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// ToFinding converts a PolicyFinding into a validated models.Finding.
// Unknown severities, empty identifiers and out-of-range scores are
// rejected so malformed policy output fails closed instead of
// producing corrupt findings.
func (f *PolicyFinding) ToFinding() (models.Finding, error) {
	if f == nil {
		return models.Finding{}, fmt.Errorf("%w: policy finding", models.ErrEmptyField)
	}
	sev := models.Severity(f.Severity)
	if !sev.Valid() {
		return models.Finding{}, fmt.Errorf("%w: %q", models.ErrInvalidSeverity, f.Severity)
	}
	return models.NewFinding(f.RuleID, f.Resource, f.Description, f.Remediation, sev, f.Score)
}

// ToFindings converts policy findings into validated model findings.
func ToFindings(pfs []*PolicyFinding) ([]*models.Finding, error) {
	out := make([]*models.Finding, 0, len(pfs))
	for _, pf := range pfs {
		f, err := pf.ToFinding()
		if err != nil {
			return nil, err
		}
		c := f
		out = append(out, &c)
	}
	return out, nil
}
