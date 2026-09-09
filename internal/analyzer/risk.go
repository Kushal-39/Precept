// Package analyzer inspects normalised resources for security
// misconfigurations and emits scored findings. Each security domain is
// an independent Analyzer; a Registry dispatches resources by provider
// and orchestrates corpus-level checks.
package analyzer

import (
	"fmt"
	"slices"
	"strings"

	"github.com/precept/precept/internal/models"
)

// severityBands maps each severity to the inclusive score range that
// findings of that severity may occupy.
var severityBands = map[models.Severity][2]int{
	models.SeverityCritical: {90, 100},
	models.SeverityHigh:     {70, 89},
	models.SeverityMedium:   {40, 69},
	models.SeverityLow:      {1, 39},
}

// rule describes one static security check. Descriptions are printf
// format strings; BaseScore is clamped into the severity band.
type rule struct {
	ID          string
	Severity    models.Severity
	BaseScore   int
	Description string
	Remediation string
}

// clampScore pins base into the band for its severity so a misconfigured
// rule can never emit a score that contradicts its label.
func clampScore(sev models.Severity, base int) int {
	band, ok := severityBands[sev]
	if !ok {
		return base
	}
	if base < band[0] {
		return band[0]
	}
	if base > band[1] {
		return band[1]
	}
	return base
}

// newFinding builds a Finding from a rule. Rule fields are compile-time
// constants, so the underlying constructor's validation cannot fail; a
// nil return therefore indicates an invalid rule definition and the
// finding is dropped rather than propagated.
func newFinding(r rule, resourceID string, args ...any) *models.Finding {
	description := r.Description
	if len(args) > 0 {
		description = fmt.Sprintf(r.Description, args...)
	}
	f, err := models.NewFinding(r.ID, resourceID, description, r.Remediation, r.Severity, clampScore(r.Severity, r.BaseScore))
	if err != nil {
		return nil
	}
	return &f
}

// MaxScore returns the highest risk score among findings, or 0 when the
// list is empty.
func MaxScore(findings []*models.Finding) int {
	max := 0
	for _, f := range findings {
		if f.RiskScore > max {
			max = f.RiskScore
		}
	}
	return max
}

// SortFindings orders findings by descending score, then rule ID, then
// resource ID, giving every scan a deterministic output order.
func SortFindings(findings []*models.Finding) {
	slices.SortFunc(findings, func(a, b *models.Finding) int {
		if a.RiskScore != b.RiskScore {
			return b.RiskScore - a.RiskScore
		}
		if a.RuleID != b.RuleID {
			return strings.Compare(a.RuleID, b.RuleID)
		}
		return strings.Compare(a.Resource, b.Resource)
	})
}
