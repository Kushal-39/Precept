// Command precept is the entry point for the Precept cloud security
// posture and detection platform.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/precept/precept/cmd/precept/cmd"
)

func main() {
	err := cmd.Execute()
	if err == nil {
		os.Exit(0)
	}
	var exitErr *cmd.ExitError
	if errors.As(err, &exitErr) {
		if !exitErr.Silent() {
			fmt.Fprintln(os.Stderr, exitErr.Message)
		}
		os.Exit(exitErr.Code)
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
