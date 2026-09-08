package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/precept/precept/internal/models"
)

// IAMParser parses AWS IAM policy documents into one resource per
// statement. The IAM schema is closed, so unknown fields are rejected.
type IAMParser struct {
	maxBytes int64
}

// NewIAMParser returns an IAM parser with the given per-file size limit;
// zero or less selects MaxFileSize.
func NewIAMParser(maxBytes int64) *IAMParser {
	return &IAMParser{maxBytes: maxBytes}
}

// SupportedExtensions returns the IAM file extensions this parser accepts.
func (p *IAMParser) SupportedExtensions() []string {
	return []string{".json"}
}

// Parse reads path and normalises every policy statement into a Resource.
func (p *IAMParser) Parse(path string) ([]*models.Resource, error) {
	data, err := readFileLimited(path, p.maxBytes)
	if err != nil {
		return nil, err
	}
	return parseIAMData(data, path)
}

type iamStringList []string

func (l *iamStringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*l = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("expected string or array of strings: %w", err)
	}
	*l = multi
	return nil
}

type iamStatement struct {
	Sid          string         `json:"Sid"`
	Effect       string         `json:"Effect"`
	Action       iamStringList  `json:"Action"`
	NotAction    iamStringList  `json:"NotAction"`
	Resource     iamStringList  `json:"Resource"`
	NotResource  iamStringList  `json:"NotResource"`
	Condition    map[string]any `json:"Condition"`
	Principal    any            `json:"Principal"`
	NotPrincipal any            `json:"NotPrincipal"`
}

type iamPolicyDocument struct {
	Version   string          `json:"Version"`
	Id        string          `json:"Id"`
	Statement json.RawMessage `json:"Statement"`
}

func parseIAMData(data []byte, path string) ([]*models.Resource, error) {
	var doc iamPolicyDocument
	if err := decodeJSONStrict(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid iam policy: %w", err)
	}
	if len(doc.Statement) == 0 {
		return nil, fmt.Errorf("%w: Statement", ErrMissingField)
	}
	statements, err := decodeIAMStatements(doc.Statement)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Resource, 0, len(statements))
	for i := range statements {
		stmt := &statements[i]
		if err := validateIAMStatement(stmt); err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		name := stmt.Sid
		if name == "" {
			name = fmt.Sprintf("statement-%d", i)
		}
		r, err := models.NewResource(fmt.Sprintf("%s#%d", path, i), "Statement", name, string(models.ResourceTypeIAM), iamProperties(stmt))
		if err != nil {
			return nil, err
		}
		r.Metadata["file"] = path
		r.Metadata["statement_index"] = strconv.Itoa(i)
		if stmt.Sid != "" {
			r.Metadata["sid"] = stmt.Sid
		}
		if doc.Version != "" {
			r.Metadata["policy_version"] = doc.Version
		}
		if doc.Id != "" {
			r.Metadata["policy_id"] = doc.Id
		}
		out = append(out, r)
	}
	return out, nil
}

func decodeIAMStatements(raw json.RawMessage) ([]iamStatement, error) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	var statements []iamStatement
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := decodeJSONStrict(raw, &statements); err != nil {
			return nil, fmt.Errorf("invalid iam policy: %w", err)
		}
		return statements, nil
	}
	var single iamStatement
	if err := decodeJSONStrict(raw, &single); err != nil {
		return nil, fmt.Errorf("invalid iam policy: %w", err)
	}
	return []iamStatement{single}, nil
}

func validateIAMStatement(stmt *iamStatement) error {
	switch stmt.Effect {
	case "Allow", "Deny":
	default:
		return fmt.Errorf("effect must be Allow or Deny, got %q", stmt.Effect)
	}
	if len(stmt.Action) == 0 && len(stmt.NotAction) == 0 {
		return fmt.Errorf("%w: Action or NotAction", ErrMissingField)
	}
	return nil
}

func iamProperties(stmt *iamStatement) map[string]any {
	props := map[string]any{"effect": stmt.Effect}
	if len(stmt.Action) > 0 {
		props["action"] = []string(stmt.Action)
	}
	if len(stmt.NotAction) > 0 {
		props["not_action"] = []string(stmt.NotAction)
	}
	if len(stmt.Resource) > 0 {
		props["resource"] = []string(stmt.Resource)
	}
	if len(stmt.NotResource) > 0 {
		props["not_resource"] = []string(stmt.NotResource)
	}
	if stmt.Condition != nil {
		props["condition"] = stmt.Condition
	}
	if stmt.Principal != nil {
		props["principal"] = stmt.Principal
	}
	if stmt.NotPrincipal != nil {
		props["not_principal"] = stmt.NotPrincipal
	}
	return props
}
