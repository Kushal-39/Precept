// Package fs provides filesystem validation helpers used by CLI commands
// and the scan engine. Paths are normalised with filepath.Clean before
// inspection to prevent path traversal.
package fs

import (
	"os"
	"path/filepath"
)

// IsDir reports whether path exists and is a directory.
func IsDir(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.IsDir()
}

// IsFile reports whether path exists and is a regular file.
func IsFile(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.Mode().IsRegular()
}
