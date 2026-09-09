package cmd

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/precept/precept/internal/analyzer"
	"github.com/precept/precept/internal/fs"
	"github.com/precept/precept/internal/models"
	"github.com/precept/precept/internal/output"
	"github.com/precept/precept/internal/parser"
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
Kubernetes manifests, IAM policy documents, and CloudTrail event logs.

Every detected issue becomes a scored finding. When the highest risk score
reaches the configured threshold the command exits 1, allowing CI/CD
pipelines to treat posture regressions as hard errors.`,
	Args:          cobra.ExactArgs(1),
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
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

	result, err := parser.Parse(opts.TargetPath)
	if err != nil {
		return fmt.Errorf("scan target: %w", err)
	}
	if scanVerbose {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Parsed %d files, %d resources, skipped %d, %d parse errors\n",
			len(result.Files), len(result.Resources), len(result.Skipped), len(result.Errors))
	}
	for _, pe := range result.Errors {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "parse warning: %s\n", pe.Error())
	}

	if len(result.Resources) == 0 {
		if len(result.Errors) > 0 {
			return fmt.Errorf("no resources could be parsed from %s", opts.TargetPath)
		}
		fmt.Println("No resources found to scan")
		return nil
	}

	registry := analyzer.NewRegistry()
	registry.Register(
		analyzer.NewIAMAnalyzer(),
		analyzer.NewNetworkAnalyzer(),
		analyzer.NewStorageAnalyzer(),
		analyzer.NewLoggingAnalyzer(),
	)
	findings := registry.AnalyzeBatch(result.Resources)
	analyzer.AssignIDs(findings)

	switch opts.OutputFormat {
	case models.OutputFormatJSON:
		rendered, err := output.FormatJSON(findings)
		if err != nil {
			return fmt.Errorf("format findings: %w", err)
		}
		fmt.Println(rendered)
	default:
		fmt.Print(output.FormatTable(findings, opts.Threshold))
	}

	if maxScore := analyzer.MaxScore(findings); maxScore >= opts.Threshold {
		return &ExitError{Code: 1}
	}
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
