package parser

import (
	"fmt"
	"os"
)

// CheckFileSize reports an error if the file at path exceeds maxBytes.
// A limit of zero or less selects MaxFileSize. Directories and missing
// paths are also rejected.
func CheckFileSize(path string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = MaxFileSize
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%w: %s", ErrIsADirectory, path)
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrFileTooLarge, path, info.Size(), maxBytes)
	}
	return nil
}
