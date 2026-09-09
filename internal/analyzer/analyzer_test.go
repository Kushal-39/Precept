package analyzer

import (
	"testing"

	"github.com/precept/precept/internal/models"
)

type fakeAnalyzer struct {
	name      string
	providers []models.ResourceType
	perRes    int
	batch     int
}

func (f *fakeAnalyzer) Name() string { return f.name }

func (f *fakeAnalyzer) Analyze(*models.Resource) []*models.Finding {
	out := make([]*models.Finding, f.perRes)
	for i := range out {
		f, err := models.NewFinding(fakeRuleID(f.name), "res", "d", "r", models.SeverityMedium, 50)
		if err != nil {
			continue
		}
		out[i] = &f
	}
	return out
}

func (f *fakeAnalyzer) SupportedProviders() []models.ResourceType { return f.providers }

func (f *fakeAnalyzer) AnalyzeBatch(resources []*models.Resource) []*models.Finding {
	if len(resources) == 0 {
		return nil
	}
	out := make([]*models.Finding, f.batch)
	for i := range out {
		f, err := models.NewFinding(fakeRuleID(f.name)+"B", "corpus", "d", "r", models.SeverityHigh, 75)
		if err != nil {
			continue
		}
		out[i] = &f
	}
	return out
}

func fakeRuleID(name string) string { return name + "-R" }

func mkResource(provider models.ResourceType) *models.Resource {
	r, err := models.NewResource("id-"+string(provider), "Type", "name", string(provider), nil)
	if err != nil {
		return nil
	}
	return r
}

func TestRegistryDispatch(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	iam := &fakeAnalyzer{name: "iam-a", providers: []models.ResourceType{models.ResourceTypeIAM, models.ResourceTypeTerraform}, perRes: 2}
	net := &fakeAnalyzer{name: "net-a", providers: []models.ResourceType{models.ResourceTypeTerraform}, perRes: 1}
	reg.Register(iam, net)

	iamRes := mkResource(models.ResourceTypeIAM)
	if got := len(reg.Analyze(iamRes)); got != 2 {
		t.Errorf("Analyze(iam resource) = %d findings, want 2 (iam-a only)", got)
	}
	tfRes := mkResource(models.ResourceTypeTerraform)
	if got := len(reg.Analyze(tfRes)); got != 3 {
		t.Errorf("Analyze(terraform resource) = %d findings, want 3 (both analyzers)", got)
	}
	k8sRes := mkResource(models.ResourceTypeKubernetes)
	if got := len(reg.Analyze(k8sRes)); got != 0 {
		t.Errorf("Analyze(kubernetes resource) = %d findings, want 0", got)
	}
}

func TestRegistryAnalyzeBatch(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(
		&fakeAnalyzer{name: "plain", providers: []models.ResourceType{models.ResourceTypeIAM}, perRes: 1},
		&fakeAnalyzer{name: "batchy", providers: []models.ResourceType{models.ResourceTypeIAM}, perRes: 1, batch: 1},
	)
	resources := []*models.Resource{mkResource(models.ResourceTypeIAM), mkResource(models.ResourceTypeIAM)}

	findings := reg.AnalyzeBatch(resources)
	if len(findings) != 5 {
		t.Fatalf("AnalyzeBatch() = %d findings, want 5 (2 plain per-resource + 2 batchy per-resource + 1 batch)", len(findings))
	}
	scores := make([]int, 0, len(findings))
	for _, f := range findings {
		scores = append(scores, f.RiskScore)
	}
	if scores[0] < scores[len(scores)-1] {
		t.Errorf("findings not sorted descending by score: %v", scores)
	}
}

func TestRegistryAnalyzeBatchEmpty(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(&fakeAnalyzer{name: "batchy", providers: []models.ResourceType{models.ResourceTypeIAM}, perRes: 1, batch: 1})
	if got := reg.AnalyzeBatch(nil); len(got) != 0 {
		t.Errorf("AnalyzeBatch(nil) = %d findings, want 0 (batch skips empty corpus)", len(got))
	}
}

func TestRegistryConcurrentRegister(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			reg.Register(&fakeAnalyzer{name: "x", providers: []models.ResourceType{models.ResourceTypeIAM}})
			_ = reg.Analyzers()
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	if got := len(reg.Analyzers()); got != 4 {
		t.Errorf("registry holds %d analyzers, want 4", got)
	}
}

func TestAssignIDs(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(&fakeAnalyzer{name: "a", providers: []models.ResourceType{models.ResourceTypeIAM}, perRes: 12})
	findings := reg.AnalyzeBatch([]*models.Resource{mkResource(models.ResourceTypeIAM)})
	AssignIDs(findings)
	if findings[0].ID != "F-001" {
		t.Errorf("first ID = %q, want F-001", findings[0].ID)
	}
	if findings[11].ID != "F-012" {
		t.Errorf("twelfth ID = %q, want F-012", findings[11].ID)
	}
}

func TestAssignIDsPadding(t *testing.T) {
	t.Parallel()
	f1, err := models.NewFinding("R", "res", "d", "r", models.SeverityLow, 1)
	if err != nil {
		t.Fatalf("NewFinding error: %v", err)
	}
	findings := []*models.Finding{&f1}
	AssignIDs(findings)
	if findings[0].ID != "F-001" {
		t.Errorf("ID = %q, want F-001", findings[0].ID)
	}
	var many []*models.Finding
	for i := 0; i < 100; i++ {
		f, err := models.NewFinding("R", "res", "d", "r", models.SeverityLow, 1)
		if err != nil {
			t.Fatalf("NewFinding error: %v", err)
		}
		many = append(many, &f)
	}
	AssignIDs(many)
	if many[9].ID != "F-010" || many[99].ID != "F-100" {
		t.Errorf("padding wrong: %q, %q", many[9].ID, many[99].ID)
	}
}
