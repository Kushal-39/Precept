package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func TestParseDirectoryMixed(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "mixed"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	// mixed tree: terraform_state.json (2), stack.tf.json (2),
	// pod.yaml (1), policy.json (2), admin_policy.json (2),
	// events.json (2), nested/more.yaml (3)
	if len(result.Resources) != 14 {
		t.Errorf("Parse() returned %d resources, want 14", len(result.Resources))
	}
	if len(result.Files) != 7 {
		t.Errorf("Parse() parsed %d files, want 7", len(result.Files))
	}
	if len(result.Errors) != 0 {
		t.Errorf("Parse() errors = %v, want none", result.Errors)
	}
	if len(result.Skipped) != 1 {
		t.Errorf("Parse() skipped = %v, want only notes.txt", result.Skipped)
	}
	byFormat := map[models.ResourceType]int{}
	for _, r := range result.Resources {
		byFormat[r.Provider]++
	}
	want := map[models.ResourceType]int{
		models.ResourceTypeTerraform:  4,
		models.ResourceTypeKubernetes: 4,
		models.ResourceTypeIAM:        4,
		models.ResourceTypeCloudTrail: 2,
	}
	for format, count := range want {
		if byFormat[format] != count {
			t.Errorf("%s resources = %d, want %d", format, byFormat[format], count)
		}
	}
	for _, r := range result.Resources {
		if r.ID == "" || r.Type == "" || r.Properties == nil {
			t.Errorf("resource %v incompletely populated", r)
		}
	}
}

func TestParseSingleFileExplicit(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "terraform", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 2 {
		t.Errorf("Parse() returned %d resources, want 2", len(result.Resources))
	}
	if len(result.Files) != 1 || result.Files[0].Format != models.ResourceTypeTerraform {
		t.Errorf("Files = %v, want one terraform file", result.Files)
	}
}

func TestParseSingleIAMFileIsNotConfusedWithTerraform(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "iam", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 2 || result.Resources[0].Provider != models.ResourceTypeIAM {
		t.Fatalf("Parse() = %v, want two IAM resources", result.Resources)
	}
}

func TestParseSingleCloudTrailFile(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "cloudtrail", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 2 || result.Resources[0].Provider != models.ResourceTypeCloudTrail {
		t.Fatalf("Parse() = %v, want two CloudTrail resources", result.Resources)
	}
}

func TestParseSingleYAMLFile(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "kubernetes", "multi_doc.yaml"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 3 {
		t.Errorf("Parse() returned %d resources, want 3", len(result.Resources))
	}
	if len(result.Files) != 1 || result.Files[0].Format != models.ResourceTypeKubernetes {
		t.Errorf("Files = %v, want one kubernetes file", result.Files)
	}
}

func TestParseCollectsNonFatalErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.tfstate")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	good := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(good, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\ndata:\n  a: b\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	result, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 1 {
		t.Errorf("Parse() returned %d resources, want 1 (good file still parses)", len(result.Resources))
	}
	if len(result.Errors) != 1 {
		t.Fatalf("Parse() errors = %v, want 1", result.Errors)
	}
	if !errors.Is(result.Errors[0].Err, result.Errors[0].Err) || result.Errors[0].Path != bad {
		t.Errorf("ParseError.Path = %q, want %q", result.Errors[0].Path, bad)
	}
}

func TestParseSizeLimitOption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := filepath.Join(dir, "big.tfstate")
	if err := os.WriteFile(big, make([]byte, 2048), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	result, err := Parse(dir, WithMaxFileSize(1024))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Errors) != 1 || !errors.Is(result.Errors[0].Err, ErrFileTooLarge) {
		t.Errorf("Parse() errors = %v, want ErrFileTooLarge", result.Errors)
	}
}

func TestParseRejectsMissingTarget(t *testing.T) {
	t.Parallel()
	if _, err := Parse(filepath.Join("testdata", "does-not-exist")); err == nil {
		t.Error("Parse() error = nil, want stat error for missing target")
	}
}

func TestParseGitDirectorySkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatalf("Mkdir error: %v", err)
	}
	stateInGit := filepath.Join(gitDir, "terraform.tfstate")
	if err := os.WriteFile(stateInGit, []byte(`{"format_version": "1.2", "values": {"root_module": {"resources": []}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	manifest := filepath.Join(dir, "pod.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: i\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	result, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 1 {
		t.Errorf("Parse() returned %d resources, want 1 (.git skipped)", len(result.Resources))
	}
	for _, f := range result.Files {
		if filepath.Base(filepath.Dir(f.Path)) == ".git" {
			t.Errorf("parsed file inside .git: %s", f.Path)
		}
	}
}

func TestParseUnsupportedFileOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "readme.md")
	if err := os.WriteFile(path, []byte("# readme"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	result, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 0 || len(result.Files) != 0 {
		t.Errorf("Parse() = %v, want empty result", result)
	}
	if len(result.Skipped) != 1 {
		t.Errorf("Skipped = %v, want readme.md", result.Skipped)
	}
}

func TestParseStringSummary(t *testing.T) {
	t.Parallel()
	result, err := Parse(filepath.Join("testdata", "terraform", "valid.json"))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	summary := result.String()
	if summary == "" || !strings.Contains(summary, "2 resources") {
		t.Errorf("String() = %q, want resource count", summary)
	}
}

func TestDetectFormatUnresolvableJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ambiguous.json")
	if err := os.WriteFile(path, []byte(`{"unrelated": true}`), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if _, ok := detectFormat(path, ".json"); ok {
		t.Error("detectFormat() classified unrelated json, want unsupported")
	}
	if _, ok := detectFormat(path, ".md"); ok {
		t.Error("detectFormat() classified .md, want unsupported")
	}
	if format, ok := detectFormat(path, ".yaml"); !ok || format != models.ResourceTypeKubernetes {
		t.Error("detectFormat(.yaml) should return kubernetes")
	}
	configPath := filepath.Join(dir, "config.tf.json")
	if err := os.WriteFile(configPath, []byte(`{"resource": {}}`), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if format, ok := detectFormat(configPath, ".json"); !ok || format != models.ResourceTypeTerraform {
		t.Error("detectFormat(.tf.json suffix) should return terraform")
	}
}

func TestParseSymlinkEscapeSkipped(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.tfstate")
	if err := os.WriteFile(outsideFile, []byte(`{"format_version": "1.2", "values": {"root_module": {"resources": []}}}`), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	root := t.TempDir()
	if err := os.Symlink(outsideFile, filepath.Join(root, "leak.tfstate")); err != nil {
		t.Fatalf("Symlink error: %v", err)
	}

	result, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(result.Resources) != 0 {
		t.Errorf("Parse() returned %d resources, want 0 (symlink must not be followed)", len(result.Resources))
	}
}
