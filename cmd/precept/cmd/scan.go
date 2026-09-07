package cmd

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/precept/precept/internal/fs"
	"github.com/precept/precept/internal/models"
)

var (
	scanThreshold int
	scanOutput    string
	scanVerbose   bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan infrastructure for security misconfigurations",
	Long: `Scan analyses Infrastructure-as-Code at the target path for security
misconfigurations. Supported sources include Terraform configurations,
Kubernetes manifests, and IAM policy documents.

Every detected issue becomes a scored finding. When the highest risk score
exceeds the configured threshold the command fails, allowing CI/CD pipelines
to treat posture regressions as hard errors.`,
	Args:         cobra.ExactArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

func init() {
	scanCmd.Flags().IntVar(&scanThreshold, "threshold", models.DefaultThreshold, "risk score threshold for CI/CD failures (0-100)")
	scanCmd.Flags().StringVar(&scanOutput, "output", models.OutputFormatTable, `output format ("table" or "json")`)
	scanCmd.Flags().BoolVar(&scanVerbose, "verbose", false, "enable verbose logging")

	_ = viper.BindPFlag("scan.threshold", scanCmd.Flags().Lookup("threshold"))
	_ = viper.BindPFlag("scan.output", scanCmd.Flags().Lookup("output"))
	_ = viper.BindPFlag("scan.verbose", scanCmd.Flags().Lookup("verbose"))
}

func runScan(cmd *cobra.Command, args []string) error {
	opts, err := buildScanOptions(args[0], scanThreshold, scanOutput)
	if err != nil {
		return err
	}
	if scanVerbose {
		fmt.Printf("Output format: %s\n", opts.OutputFormat)
	}
	fmt.Printf("Scanning target: %s with threshold %d\n", opts.TargetPath, opts.Threshold)
	return nil
}

func buildScanOptions(target string, threshold int, output string) (models.ScanOptions, error) {
	if target == "" {
		return models.ScanOptions{}, errors.New("target path must not be empty")
	}
	cleaned := filepath.Clean(target)
	if !fs.IsDir(cleaned) && !fs.IsFile(cleaned) {
		return models.ScanOptions{}, fmt.Errorf("target path %q does not exist", cleaned)
	}
	if threshold < 0 || threshold > 100 {
		return models.ScanOptions{}, fmt.Errorf("threshold must be between 0 and 100, got %d", threshold)
	}
	switch output {
	case models.OutputFormatTable, models.OutputFormatJSON:
	default:
		return models.ScanOptions{}, fmt.Errorf("output format must be %q or %q, got %q", models.OutputFormatTable, models.OutputFormatJSON, output)
	}
	opts := models.ScanOptions{
		TargetPath:   cleaned,
		Threshold:    threshold,
		OutputFormat: output,
	}
	if err := opts.Validate(); err != nil {
		return models.ScanOptions{}, err
	}
	return opts, nil
}
