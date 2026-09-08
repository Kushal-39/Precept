package parser

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SafePath resolves target against root and guarantees the resolved path
// stays inside root. Paths are normalised with filepath.Clean, relative
// targets are joined to root, and both root and target are evaluated
// through symlinks so a link pointing outside the root is rejected. This
// prevents path traversal when scanning untrusted directory trees.
func SafePath(root, target string) (string, error) {
	if root == "" {
		return "", errors.New("root must not be empty")
	}
	if target == "" {
		return "", errors.New("target must not be empty")
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}

	clean := filepath.Clean(target)
	if !filepath.IsAbs(clean) {
		clean = filepath.Join(rootAbs, clean)
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		dirReal, derr := filepath.EvalSymlinks(filepath.Dir(clean))
		if derr != nil {
			return "", fmt.Errorf("resolve path: %w", derr)
		}
		real = filepath.Join(dirReal, filepath.Base(clean))
	}

	rel, err := filepath.Rel(rootReal, real)
	if err != nil {
		return "", fmt.Errorf("relate path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s resolves outside %s", ErrPathOutsideRoot, target, root)
	}
	return real, nil
}
