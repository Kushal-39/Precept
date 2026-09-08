package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/precept/precept/internal/models"
)

// Option customises the unified parser.
type Option func(*unified)

// WithMaxFileSize overrides the per-file size limit in bytes. Values of
// zero or less select MaxFileSize.
func WithMaxFileSize(maxBytes int64) Option {
	return func(u *unified) {
		if maxBytes > 0 {
			u.maxBytes = maxBytes
		}
	}
}

type unified struct {
	maxBytes int64
}

// Parse normalises the file or directory tree at target into resources.
// Files are dispatched by extension; for ambiguous .json files the top
// level is inspected to distinguish Terraform, IAM, and CloudTrail
// documents. Directory scans recurse deterministically in lexical order,
// skipping .git directories and symlinked paths. Per-file failures are
// collected in the returned ParseResult and do not abort the scan; the
// result is nil only when target itself cannot be processed.
func Parse(target string, opts ...Option) (*ParseResult, error) {
	u := &unified{maxBytes: MaxFileSize}
	for _, opt := range opts {
		opt(u)
	}
	cleaned := filepath.Clean(target)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}

	root := abs
	result := &ParseResult{Target: abs}
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = u.walkDir(rootReal, result)
	} else {
		err = u.parseFile(rootReal, abs, result)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (u *unified) walkDir(root string, result *ParseResult) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, ParseError{Path: path, Err: err})
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" && path != root {
				return filepath.SkipDir
			}
			if path != root {
				if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		return u.parseFile(root, path, result)
	})
}

func (u *unified) parseFile(root, path string, result *ParseResult) error {
	ext := strings.ToLower(filepath.Ext(path))
	format, ok := detectFormat(path, ext)
	if !ok {
		result.Skipped = append(result.Skipped, path)
		return nil
	}
	if _, err := SafePath(root, path); err != nil {
		result.Errors = append(result.Errors, ParseError{Path: path, Err: err})
		return nil
	}
	p := u.parserFor(format)
	resources, err := p.Parse(path)
	if err != nil {
		result.Errors = append(result.Errors, ParseError{Path: path, Err: err})
		return nil
	}
	result.Files = append(result.Files, FileMeta{Path: path, Format: format})
	result.Resources = append(result.Resources, resources...)
	return nil
}

func (u *unified) parserFor(format models.ResourceType) Parser {
	switch format {
	case models.ResourceTypeTerraform:
		return NewTerraformParser(u.maxBytes)
	case models.ResourceTypeKubernetes:
		return NewKubernetesParser(u.maxBytes)
	case models.ResourceTypeIAM:
		return NewIAMParser(u.maxBytes)
	case models.ResourceTypeCloudTrail:
		return NewCloudTrailParser(u.maxBytes)
	default:
		return nil
	}
}

// jsonMarkers maps top-level JSON keys to the format they identify.
var jsonMarkers = []struct {
	key    string
	format models.ResourceType
}{
	{"format_version", models.ResourceTypeTerraform},
	{"planned_values", models.ResourceTypeTerraform},
	{"resource_changes", models.ResourceTypeTerraform},
	{"Statement", models.ResourceTypeIAM},
	{"Records", models.ResourceTypeCloudTrail},
	{"eventVersion", models.ResourceTypeCloudTrail},
}

// detectFormat resolves the source format for path. YAML extensions map
// to Kubernetes. Terraform state and config suffixes map to Terraform.
// A plain .json file is classified by inspecting its top-level keys;
// files with no resolvable format are reported as unsupported.
func detectFormat(path, ext string) (models.ResourceType, bool) {
	name := strings.ToLower(path)
	switch {
	case strings.HasSuffix(name, ".tf.json"),
		strings.HasSuffix(name, ".tfstate.json"),
		strings.HasSuffix(name, ".tfstate"):
		return models.ResourceTypeTerraform, true
	}
	switch ext {
	case ".yaml", ".yml":
		return models.ResourceTypeKubernetes, true
	case ".json":
		return classifyJSON(path)
	default:
		return "", false
	}
}

// jsonPeekLimit bounds how much of a .json file is read during format
// classification. Every supported format carries its identifying keys in
// the leading top-level fields, so a file without an early marker is not
// parseable by Precept regardless of its total size.
const jsonPeekLimit int64 = 64 << 10

// classifyJSON identifies the source format of a .json file by streaming
// its top-level keys without loading the whole document into memory.
func classifyJSON(path string) (models.ResourceType, bool) {
	// The handle is only used to stream header tokens for classification.
	// #nosec G304 -- path traversal is prevented by SafePath containment checks.
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	dec := json.NewDecoder(io.LimitReader(f, jsonPeekLimit))
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	if d, ok := tok.(json.Delim); !ok || d != json.Delim('{') {
		return "", false
	}
	seen := map[models.ResourceType]bool{}
	sawResource := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		key, ok := keyTok.(string)
		if !ok {
			break
		}
		if key == "resource" {
			sawResource = true
		}
		for _, marker := range jsonMarkers {
			if marker.key == key {
				seen[marker.format] = true
			}
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			break
		}
	}
	switch {
	case len(seen) == 1:
		for format := range seen {
			return format, true
		}
	case len(seen) == 0 && sawResource:
		return models.ResourceTypeTerraform, true
	}
	return "", false
}

// String renders a ParseResult summary for logging and CLI output.
func (r *ParseResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "target %s: %d resources from %d files", r.Target, len(r.Resources), len(r.Files))
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, ", %d errors", len(r.Errors))
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, ", %d skipped", len(r.Skipped))
	}
	return b.String()
}
