package models

import (
	"encoding/json"
	"testing"
)

func TestNewScanOptionsDefaults(t *testing.T) {
	o := NewScanOptions("./infra")
	if o.TargetPath != "./infra" {
		t.Errorf("TargetPath = %q, want %q", o.TargetPath, "./infra")
	}
	if o.Threshold != DefaultThreshold {
		t.Errorf("Threshold = %d, want %d", o.Threshold, DefaultThreshold)
	}
	if o.OutputFormat != OutputFormatTable {
		t.Errorf("OutputFormat = %q, want %q", o.OutputFormat, OutputFormatTable)
	}
	if err := o.Validate(); err != nil {
		t.Errorf("Validate() on defaults error = %v, want nil", err)
	}
}

func TestScanOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		options ScanOptions
		wantErr bool
	}{
		{"table format", ScanOptions{TargetPath: ".", Threshold: 70, OutputFormat: OutputFormatTable}, false},
		{"json format", ScanOptions{TargetPath: ".", Threshold: 70, OutputFormat: OutputFormatJSON}, false},
		{"empty format", ScanOptions{TargetPath: ".", Threshold: 70, OutputFormat: ""}, true},
		{"unknown format", ScanOptions{TargetPath: ".", Threshold: 70, OutputFormat: "yaml"}, true},
		{"case sensitive format", ScanOptions{TargetPath: ".", Threshold: 70, OutputFormat: "JSON"}, true},
		{"threshold boundary zero", ScanOptions{TargetPath: ".", Threshold: 0, OutputFormat: OutputFormatTable}, false},
		{"threshold boundary hundred", ScanOptions{TargetPath: ".", Threshold: 100, OutputFormat: OutputFormatJSON}, false},
		{"threshold negative", ScanOptions{TargetPath: ".", Threshold: -1, OutputFormat: OutputFormatTable}, true},
		{"threshold above hundred", ScanOptions{TargetPath: ".", Threshold: 101, OutputFormat: OutputFormatTable}, true},
		{"empty target path allowed", ScanOptions{TargetPath: "", Threshold: 70, OutputFormat: OutputFormatTable}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanOptionsJSONRoundTrip(t *testing.T) {
	want := ScanOptions{TargetPath: "/iac", Threshold: 42, OutputFormat: OutputFormatJSON}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	var got ScanOptions
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if got != want {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestScanOptionsJSONEmptyStruct(t *testing.T) {
	data, err := json.Marshal(ScanOptions{})
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	want := `{"target_path":"","threshold":0,"output_format":""}`
	if string(data) != want {
		t.Errorf("empty struct JSON = %s, want %s", data, want)
	}
}
