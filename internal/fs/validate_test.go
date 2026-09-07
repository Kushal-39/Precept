package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "config.tf")
	if err := os.WriteFile(file, []byte("resource"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"existing directory", dir, true},
		{"trailing slash", dir + "/", true},
		{"dot relative", ".", true},
		{"dirty path", dir + "/./", true},
		{"empty path", "", false},
		{"missing path", filepath.Join(dir, "missing"), false},
		{"regular file is not dir", file, false},
		{"path under missing dir", filepath.Join(dir, "missing", "nested"), false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsDir(tt.path); got != tt.want {
				t.Errorf("IsDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"existing file", file, true},
		{"dirty path", dir + "/./policy.json", true},
		{"empty path", "", false},
		{"missing file", filepath.Join(dir, "missing.json"), false},
		{"directory is not file", dir, false},
		{"path under missing dir", filepath.Join(dir, "missing", "a.json"), false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsFile(tt.path); got != tt.want {
				t.Errorf("IsFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
