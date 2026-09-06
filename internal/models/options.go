package models

import "fmt"

// Supported output formats for scan results.
const (
	OutputFormatTable = "table"
	OutputFormatJSON  = "json"
)

// DefaultThreshold is the default RiskScore a scan must not exceed to pass.
const DefaultThreshold = 70

// ScanOptions configures a single scan run.
type ScanOptions struct {
	TargetPath   string `json:"target_path"`
	Threshold    int    `json:"threshold"`
	OutputFormat string `json:"output_format"`
}

// NewScanOptions returns ScanOptions for targetPath with defaults applied.
func NewScanOptions(targetPath string) ScanOptions {
	return ScanOptions{
		TargetPath:   targetPath,
		Threshold:    DefaultThreshold,
		OutputFormat: OutputFormatTable,
	}
}

// Validate reports whether the options carry a usable configuration.
func (o ScanOptions) Validate() error {
	switch o.OutputFormat {
	case OutputFormatTable, OutputFormatJSON:
	default:
		return fmt.Errorf("invalid output format %q", o.OutputFormat)
	}
	if o.Threshold < 0 || o.Threshold > 100 {
		return fmt.Errorf("threshold out of range [0, 100]: got %d", o.Threshold)
	}
	return nil
}
