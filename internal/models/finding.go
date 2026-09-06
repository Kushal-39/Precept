// Package models defines the core data structures shared across all
// Precept modules. Models are pure data transfer objects: they carry no
// logging, I/O, or behavioural dependencies.
package models

import (
	"errors"
	"fmt"
	"time"
)

// Severity classifies the criticality of a Finding.
type Severity string

// Recognised severity levels, ordered from most to least critical.
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Errors returned by NewFinding when validation fails.
var (
	ErrInvalidSeverity = errors.New("invalid severity")
	ErrScoreOutOfRange = errors.New("risk score out of range [0, 100]")
	ErrEmptyField      = errors.New("required field is empty")
)

// Valid reports whether s is a recognised severity level.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// Finding represents a single security issue detected during a scan.
type Finding struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Resource    string    `json:"resource"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	RiskScore   int       `json:"risk_score"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewFinding constructs a validated Finding with Timestamp set to the
// current time. ruleID, resource and description are required; score must
// be within 0-100 and severity must be a recognised level. ID is assigned
// later by the scan engine.
func NewFinding(ruleID, resource, description, remediation string, severity Severity, score int) (Finding, error) {
	if ruleID == "" {
		return Finding{}, fmt.Errorf("%w: ruleID", ErrEmptyField)
	}
	if resource == "" {
		return Finding{}, fmt.Errorf("%w: resource", ErrEmptyField)
	}
	if description == "" {
		return Finding{}, fmt.Errorf("%w: description", ErrEmptyField)
	}
	if !severity.Valid() {
		return Finding{}, fmt.Errorf("%w: %q", ErrInvalidSeverity, severity)
	}
	if score < 0 || score > 100 {
		return Finding{}, fmt.Errorf("%w: got %d", ErrScoreOutOfRange, score)
	}
	return Finding{
		RuleID:      ruleID,
		Resource:    resource,
		Severity:    severity,
		Description: description,
		Remediation: remediation,
		RiskScore:   score,
		Timestamp:   time.Now(),
	}, nil
}
