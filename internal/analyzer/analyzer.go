package analyzer

import (
	"slices"
	"sync"

	"github.com/precept/precept/internal/models"
)

// Analyzer inspects individual resources for misconfigurations in one
// security domain.
type Analyzer interface {
	Name() string
	Analyze(resource *models.Resource) []*models.Finding
	SupportedProviders() []models.ResourceType
}

// BatchAnalyzer inspects the full resource set of a scan. Implementations
// cover checks that no single resource can answer, such as detecting the
// absence of a resource type entirely.
type BatchAnalyzer interface {
	Analyzer
	AnalyzeBatch(resources []*models.Resource) []*models.Finding
}

// Registry dispatches resources to the analyzers that support their
// provider and orchestrates corpus-level batch checks.
type Registry struct {
	mu        sync.Mutex
	analyzers []Analyzer
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds analyzers to the registry.
func (r *Registry) Register(as ...Analyzer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzers = append(r.analyzers, as...)
}

// Analyzers returns the registered analyzers in registration order.
func (r *Registry) Analyzers() []Analyzer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.analyzers)
}

// Analyze dispatches resource to every registered analyzer that supports
// its provider and returns the combined findings. Batch-only analyzers
// are skipped here; call AnalyzeBatch for corpus-level checks.
func (r *Registry) Analyze(resource *models.Resource) []*models.Finding {
	var findings []*models.Finding
	for _, a := range r.Analyzers() {
		if !slices.Contains(a.SupportedProviders(), resource.Provider) {
			continue
		}
		findings = append(findings, a.Analyze(resource)...)
	}
	return findings
}

// AnalyzeBatch runs per-resource dispatch across every resource, then
// invokes batch-capable analyzers once each with the full set. Findings
// are sorted before returning.
func (r *Registry) AnalyzeBatch(resources []*models.Resource) []*models.Finding {
	var findings []*models.Finding
	for _, resource := range resources {
		findings = append(findings, r.Analyze(resource)...)
	}
	for _, a := range r.Analyzers() {
		if ba, ok := a.(BatchAnalyzer); ok {
			findings = append(findings, ba.AnalyzeBatch(resources)...)
		}
	}
	SortFindings(findings)
	return findings
}

// AssignIDs stamps sequential identifiers onto findings in their current
// order, honouring the model rule that the engine owns Finding.ID.
func AssignIDs(findings []*models.Finding) {
	for i, f := range findings {
		f.ID = "F-" + padID(i+1)
	}
}

func padID(n int) string {
	switch {
	case n < 10:
		return "00" + itoa(n)
	case n < 100:
		return "0" + itoa(n)
	default:
		return itoa(n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
