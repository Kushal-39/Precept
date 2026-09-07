// Command precept is the entry point for the Precept cloud security
// posture and detection platform.
package main

import (
	"os"

	"github.com/precept/precept/cmd/precept/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
