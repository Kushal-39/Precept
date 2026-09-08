package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/precept/precept/internal/models"
	"gopkg.in/yaml.v3"
)

// KubernetesParser parses Kubernetes YAML manifests, including files with
// multiple documents separated by --- and List envelopes containing items.
type KubernetesParser struct {
	maxBytes int64
}

// NewKubernetesParser returns a Kubernetes parser with the given per-file
// size limit; zero or less selects MaxFileSize.
func NewKubernetesParser(maxBytes int64) *KubernetesParser {
	return &KubernetesParser{maxBytes: maxBytes}
}

// SupportedExtensions returns the Kubernetes file extensions this parser accepts.
func (p *KubernetesParser) SupportedExtensions() []string {
	return []string{".yaml", ".yml"}
}

// Parse reads path and normalises every manifest document into a Resource.
// Document decoding is strict at the top level: fields outside the curated
// manifest envelope are rejected. Bodies of spec, metadata and data maps
// remain open so custom resources and arbitrary workloads still parse.
func (p *KubernetesParser) Parse(path string) ([]*models.Resource, error) {
	data, err := readFileLimited(path, p.maxBytes)
	if err != nil {
		return nil, err
	}
	return parseKubernetesData(data, path)
}

// k8sManifest is the curated strict envelope for top-level manifest fields.
type k8sManifest struct {
	APIVersion      string         `yaml:"apiVersion"`
	Kind            string         `yaml:"kind"`
	Metadata        map[string]any `yaml:"metadata"`
	Spec            map[string]any `yaml:"spec"`
	Data            map[string]any `yaml:"data"`
	StringData      map[string]any `yaml:"stringData"`
	BinaryData      map[string]any `yaml:"binaryData"`
	Type            string         `yaml:"type"`
	Rules           []any          `yaml:"rules"`
	RoleRef         map[string]any `yaml:"roleRef"`
	Subjects        []any          `yaml:"subjects"`
	AggregationRule map[string]any `yaml:"aggregationRule"`
	Immutable       *bool          `yaml:"immutable"`
	Status          map[string]any `yaml:"status"`
	Items           []any          `yaml:"items"`
}

func parseKubernetesData(data []byte, path string) ([]*models.Resource, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var out []*models.Resource
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid kubernetes yaml: %w", err)
		}
		inner := node.Content
		if len(inner) == 0 {
			continue
		}
		root := inner[0]
		if root.Tag == "!!null" {
			continue
		}
		doc, err := decodeManifestNode(root)
		if err != nil {
			return nil, err
		}
		resources, err := manifestToResources(doc, path)
		if err != nil {
			return nil, err
		}
		out = append(out, resources...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyFile, path)
	}
	return out, nil
}

func decodeManifestNode(root *yaml.Node) (*k8sManifest, error) {
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid kubernetes yaml: document must be a mapping, got %s", root.Tag)
	}
	raw, err := yaml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("invalid kubernetes yaml: %w", err)
	}
	strict := yaml.NewDecoder(bytes.NewReader(raw))
	strict.KnownFields(true)
	var doc k8sManifest
	if err := strict.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid kubernetes yaml: %w", err)
	}
	return &doc, nil
}

func manifestToResources(doc *k8sManifest, path string) ([]*models.Resource, error) {
	if doc.Kind == "" {
		return nil, fmt.Errorf("%w: kind", ErrMissingField)
	}
	if doc.APIVersion == "" {
		return nil, fmt.Errorf("%w: apiVersion", ErrMissingField)
	}
	if doc.Kind == "List" {
		return expandK8sList(doc, path)
	}
	name, _ := doc.Metadata["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("%w: metadata.name", ErrMissingField)
	}
	namespace, _ := doc.Metadata["namespace"].(string)
	id := doc.Kind + "/" + name
	if namespace != "" {
		id = doc.Kind + "/" + namespace + "/" + name
	}
	r, err := models.NewResource(id, doc.Kind, name, string(models.ResourceTypeKubernetes), k8sProperties(doc))
	if err != nil {
		return nil, err
	}
	r.Metadata["file"] = path
	r.Metadata["api_version"] = doc.APIVersion
	if namespace != "" {
		r.Metadata["namespace"] = namespace
	}
	return []*models.Resource{r}, nil
}

func expandK8sList(doc *k8sManifest, path string) ([]*models.Resource, error) {
	var out []*models.Resource
	for i, item := range doc.Items {
		raw, err := yaml.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("list item %d: %w", i, err)
		}
		resources, err := parseKubernetesData(raw, path)
		if err != nil {
			return nil, fmt.Errorf("list item %d: %w", i, err)
		}
		out = append(out, resources...)
	}
	return out, nil
}

func k8sProperties(doc *k8sManifest) map[string]any {
	props := map[string]any{}
	addMapIf := func(key string, m map[string]any) {
		if len(m) > 0 {
			props[key] = m
		}
	}
	addMapIf("spec", doc.Spec)
	addMapIf("data", doc.Data)
	addMapIf("stringData", doc.StringData)
	addMapIf("binaryData", doc.BinaryData)
	addMapIf("roleRef", doc.RoleRef)
	addMapIf("aggregationRule", doc.AggregationRule)
	addMapIf("status", doc.Status)
	if doc.Type != "" {
		props["type"] = doc.Type
	}
	if len(doc.Rules) > 0 {
		props["rules"] = doc.Rules
	}
	if len(doc.Subjects) > 0 {
		props["subjects"] = doc.Subjects
	}
	if doc.Immutable != nil {
		props["immutable"] = *doc.Immutable
	}
	meta := map[string]any{}
	for _, key := range []string{"labels", "annotations"} {
		if v, ok := doc.Metadata[key]; ok {
			meta[key] = v
		}
	}
	if len(meta) > 0 {
		props["metadata"] = meta
	}
	return props
}
