package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestKubernetesSupportedExtensions(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	got := p.SupportedExtensions()
	for _, want := range []string{".yaml", ".yml"} {
		if !contains(got, want) {
			t.Errorf("SupportedExtensions() missing %q in %v", want, got)
		}
	}
}

func TestKubernetesParsePod(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "kubernetes", "valid.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("Parse() returned %d resources, want 1", len(resources))
	}
	r := resources[0]
	if r.ID != "Pod/default/api" {
		t.Errorf("ID = %q, want Pod/default/api", r.ID)
	}
	if r.Type != "Pod" || r.Name != "api" {
		t.Errorf("Type/Name = %q/%q, want Pod/api", r.Type, r.Name)
	}
	if r.Provider != models.ResourceTypeKubernetes {
		t.Errorf("Provider = %q, want %q", r.Provider, models.ResourceTypeKubernetes)
	}
	spec, ok := r.Properties["spec"].(map[string]any)
	if !ok {
		t.Fatalf("Properties[spec] = %T, want map", r.Properties["spec"])
	}
	containers, ok := spec["containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Errorf("spec.containers = %v, want one container", spec["containers"])
	}
	meta, ok := r.Properties["metadata"].(map[string]any)
	if !ok || meta["labels"] == nil {
		t.Errorf("Properties[metadata] = %v, want labels", r.Properties["metadata"])
	}
	if got := r.Metadata["api_version"]; got != "v1" {
		t.Errorf("Metadata[api_version] = %q, want v1", got)
	}
	if got := r.Metadata["namespace"]; got != "default" {
		t.Errorf("Metadata[namespace] = %q, want default", got)
	}
}

func TestKubernetesParseMultiDoc(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "kubernetes", "multi_doc.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	wantKinds := []string{"Service", "Deployment", "Pod"}
	if len(resources) != len(wantKinds) {
		t.Fatalf("Parse() returned %d resources, want %d", len(resources), len(wantKinds))
	}
	for i, kind := range wantKinds {
		if resources[i].Type != kind {
			t.Errorf("resources[%d].Type = %q, want %q", i, resources[i].Type, kind)
		}
	}
	if got := resources[0].ID; got != "Service/default/api-svc" {
		t.Errorf("ID = %q, want Service/default/api-svc", got)
	}
	if got := resources[2].ID; got != "Pod/batch/worker" {
		t.Errorf("ID = %q, want Pod/batch/worker", got)
	}
}

func TestKubernetesParseMultiDocWithSecretsAndPolicies(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "kubernetes", "multi_doc_types.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 3 {
		t.Fatalf("Parse() returned %d resources, want 3", len(resources))
	}
	secret := resources[0]
	if secret.Type != "Secret" {
		t.Fatalf("Type = %q, want Secret", secret.Type)
	}
	if got, ok := secret.Properties["type"].(string); !ok || got != "Opaque" {
		t.Errorf("Properties[type] = %v, want Opaque", secret.Properties["type"])
	}
	if _, ok := secret.Properties["stringData"]; !ok {
		t.Error("Properties[stringData] missing")
	}
	policy := resources[1]
	if _, ok := policy.Properties["spec"]; !ok {
		t.Error("NetworkPolicy spec missing")
	}
	role := resources[2]
	if _, ok := role.Properties["rules"]; !ok {
		t.Error("Role rules missing")
	}
}

func TestKubernetesParseCustomResource(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "kubernetes", "valid_crd.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v (CRDs must parse generically)", err)
	}
	if len(resources) != 1 || resources[0].Type != "PreceptPolicy" {
		t.Fatalf("Parse() = %v, want one PreceptPolicy resource", resources)
	}
	if resources[0].Properties["spec"] == nil {
		t.Error("Properties[spec] missing")
	}
}

func TestKubernetesParseList(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	resources, err := p.Parse(filepath.Join("testdata", "kubernetes", "valid_list.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("Parse() returned %d resources, want 2", len(resources))
	}
	want := []string{"ConfigMap/cm-one", "ConfigMap/cm-two"}
	for i, id := range want {
		if resources[i].ID != id {
			t.Errorf("resources[%d].ID = %q, want %q", i, resources[i].ID, id)
		}
	}
}

func TestKubernetesTrailingSeparator(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "doc.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: one\ndata:\n  a: b\n---\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	p := NewKubernetesParser(0)
	resources, err := p.Parse(path)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v (trailing separator must be tolerated)", err)
	}
	if len(resources) != 1 {
		t.Errorf("Parse() returned %d resources, want 1", len(resources))
	}
}

func TestKubernetesParseErrors(t *testing.T) {
	t.Parallel()
	p := NewKubernetesParser(0)
	write := func(t *testing.T, data string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "manifest.yaml")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}
		return path
	}

	tests := []struct {
		name      string
		path      string
		wantErr   error
		errSubstr string
	}{
		{name: "malformed yaml", path: filepath.Join("testdata", "kubernetes", "invalid.yaml"), errSubstr: "invalid kubernetes yaml"},
		{name: "unknown top-level field", path: filepath.Join("testdata", "kubernetes", "unknown_field.yaml"), errSubstr: "invalid kubernetes yaml"},
		{name: "missing name", path: filepath.Join("testdata", "kubernetes", "missing_name.yaml"), errSubstr: "metadata.name"},
		{name: "empty file", path: filepath.Join("testdata", "kubernetes", "empty.yaml"), wantErr: ErrEmptyFile},
		{name: "only separators", path: filepath.Join("testdata", "kubernetes", "only_separators.yaml"), wantErr: ErrEmptyFile},
		{name: "missing kind", path: write(t, "apiVersion: v1\nmetadata:\n  name: x\n"), errSubstr: "kind"},
		{name: "missing apiVersion", path: write(t, "kind: Pod\nmetadata:\n  name: x\n"), errSubstr: "apiVersion"},
		{name: "sequence document", path: write(t, "- a\n- b\n"), errSubstr: "mapping"},
		{name: "scalar document", path: write(t, "just a string\n"), errSubstr: "mapping"},
		{name: "list item invalid", path: write(t, "apiVersion: v1\nkind: List\nitems:\n  - metadata:\n      name: broken\n"), errSubstr: "list item"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resources, err := p.Parse(tt.path)
			if resources != nil {
				t.Errorf("Parse() resources = %v, want nil on error", resources)
			}
			if err == nil {
				t.Fatalf("Parse() error = nil, want error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse() error = %v, want %v", err, tt.wantErr)
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("Parse() error = %q, want containing %q", err.Error(), tt.errSubstr)
			}
		})
	}
}
