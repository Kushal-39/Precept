// Package cmd implements the Precept command-line interface built on
// Cobra. Flags are bound to Viper so configuration files can override
// defaults in future modules.
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "precept",
	Short: "Precept - Cloud security posture and detection platform",
}

// Execute runs the root command. A non-nil error maps to exit code 1 in
// main; nil maps to exit code 0.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
