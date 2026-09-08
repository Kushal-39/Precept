package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafePath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sub := filepath.Join(root, "infra")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir error: %v", err)
	}
	file := filepath.Join(sub, "main.tf.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	linkOutside := filepath.Join(root, "link-outside")
	if err := os.Symlink(outside, linkOutside); err != nil {
		t.Fatalf("Symlink error: %v", err)
	}
	linkInside := filepath.Join(root, "link-inside")
	if err := os.Symlink(sub, linkInside); err != nil {
		t.Fatalf("Symlink error: %v", err)
	}

	tests := []struct {
		name    string
		root    string
		target  string
		wantErr bool
		wantSub string
	}{
		{name: "file inside root", root: root, target: "infra/main.tf.json", wantSub: "infra/main.tf.json"},
		{name: "absolute inside root", root: root, target: file, wantSub: "infra/main.tf.json"},
		{name: "root itself", root: root, target: root},
		{name: "dot relative", root: root, target: "."},
		{name: "dirty relative", root: root, target: "infra/./"},
		{name: "nested dot dot stays inside", root: root, target: "infra/../infra/main.tf.json", wantSub: "infra/main.tf.json"},
		{name: "symlink pointing inside", root: root, target: "link-inside/main.tf.json", wantSub: "infra/main.tf.json"},
		{name: "missing file inside root", root: root, target: "infra/missing.tf", wantSub: "infra/missing.tf"},
		{name: "traversal relative", root: root, target: "../../../etc/passwd", wantErr: true},
		{name: "traversal absolute", root: root, target: "/etc/passwd", wantErr: true},
		{name: "symlink pointing outside", root: root, target: "link-outside/secret.txt", wantErr: true},
		{name: "outside absolute", root: root, target: outsideFile, wantErr: true},
		{name: "empty target", root: root, target: "", wantErr: true},
		{name: "empty root", root: "", target: "x", wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := SafePath(tt.root, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SafePath(%q, %q) = %q, want error", tt.root, tt.target, got)
				}
				if tt.name == "empty target" || tt.name == "empty root" {
					return
				}
				if !errors.Is(err, ErrPathOutsideRoot) && !strings.Contains(err.Error(), "resolve") {
					t.Errorf("SafePath() error = %v, want ErrPathOutsideRoot or resolve failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("SafePath(%q, %q) unexpected error: %v", tt.root, tt.target, err)
			}
			if tt.wantSub != "" && !strings.HasSuffix(got, tt.wantSub) {
				t.Errorf("SafePath() = %q, want suffix %q", got, tt.wantSub)
			}
			rel, relErr := filepath.Rel(root, got)
			if relErr != nil || strings.HasPrefix(rel, "..") {
				t.Errorf("SafePath() = %q escapes root %q", got, root)
			}
		})
	}
}

func TestCheckFileSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	small := filepath.Join(dir, "small.json")
	if err := os.WriteFile(small, make([]byte, 100), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	exact := filepath.Join(dir, "exact.bin")
	if err := os.WriteFile(exact, make([]byte, 50), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		maxBytes int64
		wantErr  bool
	}{
		{name: "small file within limit", path: small, maxBytes: 1000},
		{name: "file exactly at limit", path: exact, maxBytes: 50},
		{name: "file over limit", path: small, maxBytes: 10, wantErr: true},
		{name: "zero limit selects default", path: small, maxBytes: 0},
		{name: "negative limit selects default", path: small, maxBytes: -1},
		{name: "directory rejected", path: dir, maxBytes: 1000, wantErr: true},
		{name: "missing file", path: filepath.Join(dir, "missing.json"), maxBytes: 1000, wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckFileSize(tt.path, tt.maxBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckFileSize(%q, %d) error = %v, wantErr %v", tt.path, tt.maxBytes, err, tt.wantErr)
			}
		})
	}
}

func TestReadFileLimited(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	data := filepath.Join(dir, "data.json")
	if err := os.WriteFile(data, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		max     int64
		want    string
		wantErr error
	}{
		{name: "reads content", path: data, max: 100, want: `{"a":1}`},
		{name: "zero limit selects default", path: data, max: 0, want: `{"a":1}`},
		{name: "empty file", path: empty, max: 100, wantErr: ErrEmptyFile},
		{name: "over limit", path: data, max: 2, wantErr: ErrFileTooLarge},
		{name: "directory", path: dir, max: 100, wantErr: ErrIsADirectory},
		{name: "missing", path: filepath.Join(dir, "missing"), max: 100},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readFileLimited(tt.path, tt.max)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("readFileLimited(%q) error = %v, want %v", tt.path, err, tt.wantErr)
				}
				return
			}
			if tt.path == filepath.Join(dir, "missing") {
				if err == nil {
					t.Error("readFileLimited(missing) error = nil, want stat error")
				}
				return
			}
			if err != nil {
				t.Fatalf("readFileLimited(%q) unexpected error: %v", tt.path, err)
			}
			if string(got) != tt.want {
				t.Errorf("readFileLimited(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDecodeJSONStrictVariants(t *testing.T) {
	t.Parallel()
	type doc struct {
		A int `json:"a"`
	}
	tests := []struct {
		name    string
		input   string
		strict  bool
		wantErr bool
	}{
		{name: "strict ok", input: `{"a":1}`, strict: true},
		{name: "strict unknown field", input: `{"a":1,"b":2}`, strict: true, wantErr: true},
		{name: "strict trailing data", input: `{"a":1} {"a":2}`, strict: true, wantErr: true},
		{name: "strict garbage", input: `not json`, strict: true, wantErr: true},
		{name: "lenient ok", input: `{"a":1}`, strict: false},
		{name: "lenient allows unknown field", input: `{"a":1,"b":2}`, strict: false},
		{name: "lenient trailing data", input: `{"a":1} {"a":2}`, strict: false, wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var d doc
			var err error
			if tt.strict {
				err = decodeJSONStrict([]byte(tt.input), &d)
			} else {
				err = decodeJSONLenient([]byte(tt.input), &d)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("decode error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
