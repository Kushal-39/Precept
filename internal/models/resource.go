package models

import (
	"errors"
	"fmt"
	"strings"
)

// ResourceType identifies the infrastructure format a Resource was
// normalised from. It doubles as the Provider discriminator so downstream
// analyzers can dispatch without string comparisons against magic values.
type ResourceType string

// Supported source formats.
const (
	ResourceTypeTerraform  ResourceType = "terraform"
	ResourceTypeKubernetes ResourceType = "kubernetes"
	ResourceTypeIAM        ResourceType = "iam"
	ResourceTypeCloudTrail ResourceType = "cloudtrail"
)

// ErrInvalidProvider is returned when a provider string is not a known format.
var ErrInvalidProvider = errors.New("invalid provider")

// Valid reports whether t is a recognised source format.
func (t ResourceType) Valid() bool {
	switch t {
	case ResourceTypeTerraform, ResourceTypeKubernetes, ResourceTypeIAM, ResourceTypeCloudTrail:
		return true
	default:
		return false
	}
}

// Resource is the normalised representation of one infrastructure element,
// regardless of the source format it was parsed from. Analyzers consume
// Resources exclusively through this shape.
type Resource struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Provider   ResourceType      `json:"provider"`
	Properties map[string]any    `json:"properties"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// NewResource constructs a validated Resource. The identifier, type, name
// and provider are required; provider must be a recognised source format.
// String fields are trimmed of surrounding whitespace and properties are
// copied so later mutation of the input map cannot alias into the Resource.
// Metadata is initialised to an empty map for callers to populate.
func NewResource(id, resourceType, name, provider string, properties map[string]any) (*Resource, error) {
	id = strings.TrimSpace(id)
	resourceType = strings.TrimSpace(resourceType)
	name = strings.TrimSpace(name)
	provider = strings.TrimSpace(provider)
	if id == "" {
		return nil, fmt.Errorf("%w: id", ErrEmptyField)
	}
	if resourceType == "" {
		return nil, fmt.Errorf("%w: resourceType", ErrEmptyField)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name", ErrEmptyField)
	}
	if provider == "" {
		return nil, fmt.Errorf("%w: provider", ErrEmptyField)
	}
	p := ResourceType(provider)
	if !p.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidProvider, provider)
	}
	props := make(map[string]any, len(properties))
	for k, v := range properties {
		props[k] = v
	}
	return &Resource{
		ID:         id,
		Type:       resourceType,
		Name:       name,
		Provider:   p,
		Properties: props,
		Metadata:   map[string]string{},
	}, nil
}
