package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precept/precept/internal/models"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = old
		_ = r.Close()
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	return string(data)
}

func resetScanFlags() {
	scanThreshold = models.DefaultThreshold
	scanOutput = models.OutputFormatTable
	scanVerbose = false
}

func runScanCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetScanFlags()
	var execErr error
	out := captureStdout(t, func() {
		rootCmd.SetArgs(append([]string{"scan"}, args...))
		execErr = rootCmd.Execute()
	})
	return out, execErr
}

func TestBuildScanOptions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(file, []byte("resource"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	tests := []struct {
		name        string
		target      string
		threshold   int
		output      string
		wantPath    string
		wantErr     bool
		errContains string
	}{
		{name: "dir target", target: dir, threshold: models.DefaultThreshold, output: models.OutputFormatTable, wantPath: dir},
		{name: "file target", target: file, threshold: 0, output: models.OutputFormatJSON, wantPath: file},
		{name: "dirty path is cleaned", target: dir + "/./", threshold: 100, output: models.OutputFormatTable, wantPath: dir},
		{name: "trailing slash is cleaned", target: dir + "/", threshold: 1, output: models.OutputFormatTable, wantPath: dir},
		{name: "threshold zero boundary", target: dir, threshold: 0, output: models.OutputFormatTable, wantPath: dir},
		{name: "threshold hundred boundary", target: dir, threshold: 100, output: models.OutputFormatTable, wantPath: dir},
		{name: "negative threshold", target: dir, threshold: -1, output: models.OutputFormatTable, wantErr: true, errContains: "threshold"},
		{name: "threshold above hundred", target: dir, threshold: 101, output: models.OutputFormatTable, wantErr: true, errContains: "threshold"},
		{name: "json output", target: dir, threshold: 70, output: models.OutputFormatJSON, wantPath: dir},
		{name: "invalid output format", target: dir, threshold: 70, output: "yaml", wantErr: true, errContains: "output format"},
		{name: "uppercase output format rejected", target: dir, threshold: 70, output: "JSON", wantErr: true, errContains: "output format"},
		{name: "empty output format", target: dir, threshold: 70, output: "", wantErr: true, errContains: "output format"},
		{name: "empty target", target: "", threshold: 70, output: models.OutputFormatTable, wantErr: true, errContains: "must not be empty"},
		{name: "missing target", target: filepath.Join(dir, "missing"), threshold: 70, output: models.OutputFormatTable, wantErr: true, errContains: "does not exist"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts, err := buildScanOptions(tt.target, tt.threshold, tt.output)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("buildScanOptions(%q, %d, %q) error = nil, want error containing %q", tt.target, tt.threshold, tt.output, tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("buildScanOptions() error = %q, want containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildScanOptions(%q, %d, %q) unexpected error: %v", tt.target, tt.threshold, tt.output, err)
			}
			if opts.TargetPath != tt.wantPath {
				t.Errorf("TargetPath = %q, want %q", opts.TargetPath, tt.wantPath)
			}
			if opts.Threshold != tt.threshold {
				t.Errorf("Threshold = %d, want %d", opts.Threshold, tt.threshold)
			}
			if opts.OutputFormat != tt.output {
				t.Errorf("OutputFormat = %q, want %q", opts.OutputFormat, tt.output)
			}
			if err := opts.Validate(); err != nil {
				t.Errorf("Validate() on built options error = %v, want nil", err)
			}
		})
	}
}

func TestScanCommand(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		args        []string
		wantOut     []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid defaults",
			args:    []string{dir},
			wantOut: []string{fmt.Sprintf("Scanning target: %s with threshold %d", dir, models.DefaultThreshold)},
		},
		{
			name:    "custom threshold and output",
			args:    []string{"--threshold=42", "--output=json", dir},
			wantOut: []string{fmt.Sprintf("Scanning target: %s with threshold 42", dir)},
		},
		{
			name:    "threshold zero boundary",
			args:    []string{"--threshold=0", dir},
			wantOut: []string{fmt.Sprintf("Scanning target: %s with threshold 0", dir)},
		},
		{
			name:    "threshold hundred boundary",
			args:    []string{"--threshold=100", dir},
			wantOut: []string{fmt.Sprintf("Scanning target: %s with threshold 100", dir)},
		},
		{
			name:    "verbose prints extra context",
			args:    []string{"--verbose", "--output=json", dir},
			wantOut: []string{"Output format: json", fmt.Sprintf("Scanning target: %s with threshold %d", dir, models.DefaultThreshold)},
		},
		{
			name:        "missing target argument",
			args:        nil,
			wantErr:     true,
			errContains: "arg",
		},
		{
			name:        "empty target argument",
			args:        []string{""},
			wantErr:     true,
			errContains: "must not be empty",
		},
		{
			name:        "nonexistent target",
			args:        []string{filepath.Join(dir, "missing")},
			wantErr:     true,
			errContains: "does not exist",
		},
		{
			name:        "negative threshold",
			args:        []string{"--threshold=-1", dir},
			wantErr:     true,
			errContains: "threshold",
		},
		{
			name:        "threshold above hundred",
			args:        []string{"--threshold=101", dir},
			wantErr:     true,
			errContains: "threshold",
		},
		{
			name:        "invalid output format",
			args:        []string{"--output=yaml", dir},
			wantErr:     true,
			errContains: "output format",
		},
		{
			name:        "empty output format",
			args:        []string{"--output=", dir},
			wantErr:     true,
			errContains: "output format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runScanCommand(t, tt.args...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("scan %v error = nil, want error containing %q", tt.args, tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("scan %v error = %q, want containing %q", tt.args, err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("scan %v unexpected error: %v", tt.args, err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("output %q does not contain %q", out, want)
				}
			}
		})
	}
}

func TestExecuteSuccessMapsToExitZero(t *testing.T) {
	resetScanFlags()
	dir := t.TempDir()
	var err error
	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"scan", dir})
		err = Execute()
	})
	if err != nil {
		t.Errorf("Execute() error = %v, want nil (main maps nil to exit 0)", err)
	}
}

func TestExecuteFailureMapsToExitOne(t *testing.T) {
	resetScanFlags()
	dir := t.TempDir()
	var err error
	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"scan", "--threshold=101", dir})
		err = Execute()
	})
	if err == nil {
		t.Error("Execute() error = nil, want error (main maps error to exit 1)")
	}
}
