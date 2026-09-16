package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/precept/precept/internal/models"
)

// PolicyEngine evaluates compiled Rego policies against normalised
// resources. The deny query is prepared once; every evaluation reuses it.
type PolicyEngine struct {
	query rego.PreparedEvalQuery
	files []string
}

// NewEngine loads every .rego policy under policyDir, compiles the
// module set and prepares the deny query. Test files, non-Rego files,
// symlinked paths and .git trees are ignored. Missing directories,
// empty policy sets and compile errors fail closed with an error.
func NewEngine(policyDir string) (*PolicyEngine, error) {
	if strings.TrimSpace(policyDir) == "" {
		return nil, errors.New("policy directory must not be empty")
	}
	cleaned := filepath.Clean(policyDir)
	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("policy directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("policy path %q is not a directory", cleaned)
	}
	files, err := discoverPolicies(cleaned)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rego policies found in %q", cleaned)
	}
	r := rego.New(
		rego.Query(QueryDeny),
		rego.Load(files, nil),
	)
	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}
	return &PolicyEngine{query: prepared, files: files}, nil
}

// Files returns the discovered policy files in evaluation order.
func (e *PolicyEngine) Files() []string {
	out := make([]string, len(e.files))
	copy(out, e.files)
	return out
}

// Evaluate runs the deny query with a single resource as input and
// returns the resulting policy findings. Nil resources, marshal
// failures, evaluation errors and undefined results fail closed.
func (e *PolicyEngine) Evaluate(resource *models.Resource) ([]*PolicyFinding, error) {
	if resource == nil {
		return nil, errors.New("policy evaluation: resource must not be nil")
	}
	if strings.TrimSpace(resource.ID) == "" {
		return nil, fmt.Errorf("%w: resource id", models.ErrEmptyField)
	}
	input, err := sanitize(resource)
	if err != nil {
		return nil, err
	}
	return e.eval(input)
}

// EvaluateCorpus runs the deny query once with the full resource set
// as input so corpus-level rules can inspect the whole scan. A nil
// slice fails closed; an empty set yields no corpus findings.
func (e *PolicyEngine) EvaluateCorpus(resources []*models.Resource) ([]*PolicyFinding, error) {
	if resources == nil {
		return nil, errors.New("policy evaluation: resources must not be nil")
	}
	raw, err := json.Marshal(resources)
	if err != nil {
		return nil, fmt.Errorf("marshal corpus: %w", err)
	}
	var decoded []any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("sanitize corpus: %w", err)
	}
	if decoded == nil {
		decoded = []any{}
	}
	return e.eval(map[string]any{"resources": decoded})
}

func (e *PolicyEngine) eval(input any) ([]*PolicyFinding, error) {
	rs, err := e.query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluate policies: %w", err)
	}
	if len(rs) == 0 {
		return nil, errors.New("evaluate policies: undefined result denies by default")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("encode policy result: %w", err)
	}
	var findings []*PolicyFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("decode policy result: %w", err)
	}
	for _, f := range findings {
		if err := validatePolicyFinding(f); err != nil {
			return nil, err
		}
	}
	if findings == nil {
		findings = []*PolicyFinding{}
	}
	return findings, nil
}

// sanitize round-trips a resource through JSON so only JSON-safe data
// crosses into policy evaluation.
func sanitize(resource *models.Resource) (any, error) {
	raw, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("marshal resource: %w", err)
	}
	var input any
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("sanitize resource: %w", err)
	}
	return input, nil
}

func validatePolicyFinding(f *PolicyFinding) error {
	if f == nil {
		return fmt.Errorf("%w: policy finding", models.ErrEmptyField)
	}
	if strings.TrimSpace(f.RuleID) == "" {
		return fmt.Errorf("%w: rule_id", models.ErrEmptyField)
	}
	if strings.TrimSpace(f.Resource) == "" {
		return fmt.Errorf("%w: resource", models.ErrEmptyField)
	}
	if strings.TrimSpace(f.Description) == "" {
		return fmt.Errorf("%w: description", models.ErrEmptyField)
	}
	if !models.Severity(f.Severity).Valid() {
		return fmt.Errorf("%w: %q", models.ErrInvalidSeverity, f.Severity)
	}
	if f.Score < 0 || f.Score > 100 {
		return fmt.Errorf("%w: got %d", models.ErrScoreOutOfRange, f.Score)
	}
	return nil
}

// discoverPolicies collects .rego files under root in lexical order,
// skipping test files, symlinked paths and .git trees.
func discoverPolicies(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" && path != root {
				return filepath.SkipDir
			}
			if path != root {
				if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover policies: %w", err)
	}
	return files, nil
}
