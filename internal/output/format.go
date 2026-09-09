// Package output renders scan findings as terminal tables or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/precept/precept/internal/analyzer"
	"github.com/precept/precept/internal/models"
)

// Fixed column widths. Severity never exceeds 8 characters, so the
// layout survives ANSI color codes wrapping the value.
const (
	colSeverity    = 10
	colRule        = 8
	colResource    = 34
	colDescription = 60
	colScore       = 5
)

var severityColor = map[models.Severity]*color.Color{
	models.SeverityCritical: color.New(color.FgRed, color.Bold),
	models.SeverityHigh:     color.New(color.FgRed),
	models.SeverityMedium:   color.New(color.FgYellow),
	models.SeverityLow:      color.New(color.FgGreen),
}

// FormatJSON renders findings as an indented JSON array. A nil or empty
// slice renders as [] rather than null so JSON consumers never see a
// bare null document.
func FormatJSON(findings []*models.Finding) (string, error) {
	if findings == nil {
		findings = []*models.Finding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	return string(data), nil
}

// FormatTable renders findings as a fixed-width table with the summary
// line appended. Severity cells are colored when color output is enabled.
func FormatTable(findings []*models.Finding, threshold int) string {
	var b strings.Builder
	writeHeader(&b)
	if len(findings) == 0 {
		writeRow(&b, "-", "-", "No findings", "No findings", 0, false)
	}
	for _, f := range findings {
		writeRow(&b, string(f.Severity), f.RuleID, f.Resource, f.Description, f.RiskScore, true)
	}
	writeSummary(&b, findings, threshold)
	return b.String()
}

func writeHeader(b *strings.Builder) {
	fmt.Fprintf(b, "%-*s  %-*s  %-*s  %-*s  %*s\n",
		colSeverity, "SEVERITY", colRule, "RULE", colResource, "RESOURCE",
		colDescription, "DESCRIPTION", colScore, "SCORE")
	fmt.Fprintf(b, "%s  %s  %s  %s  %s\n",
		strings.Repeat("-", colSeverity), strings.Repeat("-", colRule),
		strings.Repeat("-", colResource), strings.Repeat("-", colDescription),
		strings.Repeat("-", colScore))
}

func writeRow(b *strings.Builder, severity, ruleID, resource, description string, score int, colored bool) {
	if colored {
		if c, ok := severityColor[models.Severity(severity)]; ok {
			severity = c.SprintFunc()(severity)
		}
	}
	fmt.Fprintf(b, "%s  %-*s  %-*s  %-*s  %*d\n",
		severity, colRule, ruleID, colResource, truncate(resource, colResource),
		colDescription, truncate(description, colDescription), colScore, score)
}

func writeSummary(b *strings.Builder, findings []*models.Finding, threshold int) {
	maxScore := analyzer.MaxScore(findings)
	plural := "s"
	if len(findings) == 1 {
		plural = ""
	}
	status := "PASSED"
	if maxScore >= threshold {
		status = "FAILED"
	}
	summary := fmt.Sprintf("Found %d finding%s. Max risk score: %d/100. Scan %s.", len(findings), plural, maxScore, status)
	if maxScore >= threshold {
		summary = color.New(color.FgRed, color.Bold).SprintFunc()(summary)
	} else {
		summary = color.New(color.FgGreen).SprintFunc()(summary)
	}
	b.WriteString(summary)
	b.WriteString("\n")
}

func truncate(s string, width int) string {
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}
