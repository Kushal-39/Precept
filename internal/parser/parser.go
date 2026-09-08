// Package parser reads infrastructure-as-code and event-log files and
// normalises them into model.Resource values for downstream analysis.
// Supported formats: Terraform (show -json state/plan and .tf.json
// configuration), Kubernetes YAML manifests, IAM policy documents, and
// CloudTrail event logs.
package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/precept/precept/internal/models"
)

// Sentinel errors returned by parsers. Callers branch on them with errors.Is.
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrFileTooLarge      = errors.New("file exceeds size limit")
	ErrEmptyFile         = errors.New("file is empty")
	ErrIsADirectory      = errors.New("path is a directory")
	ErrPathOutsideRoot   = errors.New("path resolves outside the scan root")
	ErrMissingField      = errors.New("required field is missing")
)

// MaxFileSize is the default per-file size limit (10MB) applied when no
// explicit limit is configured. It prevents oversized inputs from exhausting
// memory during parsing.
const MaxFileSize int64 = 10 << 20

// Parser normalises one infrastructure format into resources.
type Parser interface {
	Parse(path string) ([]*models.Resource, error)
	SupportedExtensions() []string
}

// FileMeta records which file was parsed with which source format.
type FileMeta struct {
	Path   string              `json:"path"`
	Format models.ResourceType `json:"format"`
}

// ParseError couples a non-fatal parse failure to the file that caused it.
type ParseError struct {
	Path string `json:"path"`
	Err  error  `json:"-"`
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s: %v", e.Path, e.Err) }

func (e *ParseError) Unwrap() error { return e.Err }

// ParseResult aggregates the output of one scan pass over a file or
// directory tree. Resources and Files hold successes; Errors holds
// non-fatal per-file failures; Skipped holds files ignored because their
// format could not be determined.
type ParseResult struct {
	Target    string             `json:"target"`
	Resources []*models.Resource `json:"resources"`
	Files     []FileMeta         `json:"files"`
	Errors    []ParseError       `json:"errors,omitempty"`
	Skipped   []string           `json:"skipped,omitempty"`
}

// readFileLimited loads path, enforcing the per-file size limit. A limit
// of zero or less selects MaxFileSize. The size is checked before and
// after reading to close the stat/read window.
func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxFileSize
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrIsADirectory, path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrFileTooLarge, path, info.Size(), maxBytes)
	}
	// The path is resolved via SafePath by the caller and size-limited here.
	// #nosec G304 -- path traversal is prevented by SafePath containment checks.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: %s grew past %d bytes while reading", ErrFileTooLarge, path, maxBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyFile, path)
	}
	return data, nil
}

// decodeJSONStrict decodes exactly one JSON document into v, rejecting
// unknown struct fields and any trailing data after the document.
func decodeJSONStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return ensureJSONEOF(dec)
}

// decodeJSONLenient decodes exactly one JSON document into v without
// rejecting unknown fields; trailing data is still rejected.
func decodeJSONLenient(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return ensureJSONEOF(dec)
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("trailing data: %w", err)
	}
	return errors.New("trailing data after JSON document")
}
