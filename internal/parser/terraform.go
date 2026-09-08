package parser

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/precept/precept/internal/models"
)

// TerraformParser parses `terraform show -json` output (state files and
// plan JSON) and .tf.json configuration files into resources.
type TerraformParser struct {
	maxBytes int64
}

// NewTerraformParser returns a Terraform parser with the given per-file
// size limit; zero or less selects MaxFileSize.
func NewTerraformParser(maxBytes int64) *TerraformParser {
	return &TerraformParser{maxBytes: maxBytes}
}

// SupportedExtensions returns the Terraform file extensions this parser accepts.
func (p *TerraformParser) SupportedExtensions() []string {
	return []string{".tfstate", ".tfstate.json", ".tf.json"}
}

// Parse reads path and normalises every managed resource it contains.
// State-shaped input takes resources from values.root_module (recursing
// into child modules), plan-shaped input from planned_values with a
// resource_changes fallback, and .tf.json input from resource blocks.
func (p *TerraformParser) Parse(path string) ([]*models.Resource, error) {
	data, err := readFileLimited(path, p.maxBytes)
	if err != nil {
		return nil, err
	}
	if isTerraformConfig(data) {
		return p.parseConfig(path, data)
	}
	return p.parseState(path, data)
}

func isTerraformConfig(data []byte) bool {
	var peek map[string]json.RawMessage
	if err := json.Unmarshal(data, &peek); err != nil {
		return false
	}
	for _, key := range []string{"values", "planned_values", "resource_changes", "format_version"} {
		if _, ok := peek[key]; ok {
			return false
		}
	}
	_, ok := peek["resource"]
	return ok
}

type tfDocument struct {
	FormatVersion      string             `json:"format_version"`
	TerraformVersion   string             `json:"terraform_version"`
	Lineage            string             `json:"lineage"`
	SequenceNumber     json.RawMessage    `json:"sequence_number"`
	Errored            bool               `json:"errored"`
	Outputs            map[string]any     `json:"outputs"`
	Values             *tfStateValues     `json:"values"`
	PlannedValues      *tfStateValues     `json:"planned_values"`
	ResourceChanges    []tfResourceChange `json:"resource_changes"`
	ResourceDrift      json.RawMessage    `json:"resource_drift"`
	Configuration      json.RawMessage    `json:"configuration"`
	RelevantAttributes json.RawMessage    `json:"relevant_attributes"`
	Checks             json.RawMessage    `json:"checks"`
	PriorState         json.RawMessage    `json:"prior_state"`
	SensitiveValues    json.RawMessage    `json:"sensitive_values"`
}

type tfStateValues struct {
	Outputs    map[string]any `json:"outputs"`
	RootModule *tfModule      `json:"root_module"`
}

type tfModule struct {
	Address      string       `json:"address"`
	Resources    []tfResource `json:"resources"`
	ChildModules []tfModule   `json:"child_modules"`
}

type tfResource struct {
	Address         string          `json:"address"`
	Mode            string          `json:"mode"`
	Type            string          `json:"type"`
	Name            string          `json:"name"`
	Index           any             `json:"index"`
	ProviderName    string          `json:"provider_name"`
	SchemaVersion   int64           `json:"schema_version"`
	Values          map[string]any  `json:"values"`
	SensitiveValues json.RawMessage `json:"sensitive_values"`
	DependsOn       []string        `json:"depends_on"`
}

type tfResourceChange struct {
	Address         string   `json:"address"`
	Mode            string   `json:"mode"`
	Type            string   `json:"type"`
	Name            string   `json:"name"`
	Index           any      `json:"index"`
	ProviderName    string   `json:"provider_name"`
	ActionReason    string   `json:"action_reason"`
	PreviousAddress string   `json:"previous_address"`
	Change          tfChange `json:"change"`
}

type tfChange struct {
	Actions         []string        `json:"actions"`
	Before          map[string]any  `json:"before"`
	After           map[string]any  `json:"after"`
	AfterUnknown    any             `json:"after_unknown"`
	BeforeSensitive json.RawMessage `json:"before_sensitive"`
	AfterSensitive  json.RawMessage `json:"after_sensitive"`
	ReplacePaths    json.RawMessage `json:"replace_paths"`
}

type tfConfigDocument struct {
	Resource  map[string]map[string]any `json:"resource"`
	Data      map[string]map[string]any `json:"data"`
	Variable  json.RawMessage           `json:"variable"`
	Locals    json.RawMessage           `json:"locals"`
	Module    json.RawMessage           `json:"module"`
	Output    json.RawMessage           `json:"output"`
	Provider  json.RawMessage           `json:"provider"`
	Terraform json.RawMessage           `json:"terraform"`
	Moved     json.RawMessage           `json:"moved"`
}

func (p *TerraformParser) parseState(path string, data []byte) ([]*models.Resource, error) {
	var doc tfDocument
	if err := decodeJSONStrict(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid terraform json: %w", err)
	}
	var out []*models.Resource
	switch {
	case doc.Values != nil && doc.Values.RootModule != nil:
		if err := collectTerraformModule(doc.Values.RootModule, path, &out); err != nil {
			return nil, err
		}
	case doc.PlannedValues != nil && doc.PlannedValues.RootModule != nil:
		if err := collectTerraformModule(doc.PlannedValues.RootModule, path, &out); err != nil {
			return nil, err
		}
	default:
		for i := range doc.ResourceChanges {
			rc := &doc.ResourceChanges[i]
			props := rc.Change.After
			if props == nil {
				props = rc.Change.Before
			}
			if props == nil {
				props = map[string]any{}
			}
			r, err := models.NewResource(rc.Address, rc.Type, rc.Name, string(models.ResourceTypeTerraform), props)
			if err != nil {
				return nil, err
			}
			setTerraformMeta(r, path, rc.Mode, rc.ProviderName, "")
			r.Metadata["terraform_actions"] = strings.Join(rc.Change.Actions, ",")
			out = append(out, r)
		}
	}
	return out, nil
}

func collectTerraformModule(m *tfModule, path string, out *[]*models.Resource) error {
	for i := range m.Resources {
		res := &m.Resources[i]
		r, err := models.NewResource(res.Address, res.Type, res.Name, string(models.ResourceTypeTerraform), res.Values)
		if err != nil {
			return err
		}
		setTerraformMeta(r, path, res.Mode, res.ProviderName, m.Address)
		*out = append(*out, r)
	}
	for i := range m.ChildModules {
		if err := collectTerraformModule(&m.ChildModules[i], path, out); err != nil {
			return err
		}
	}
	return nil
}

func setTerraformMeta(r *models.Resource, file, mode, providerName, moduleAddr string) {
	r.Metadata["file"] = file
	if mode != "" {
		r.Metadata["terraform_mode"] = mode
	}
	if providerName != "" {
		r.Metadata["terraform_provider"] = providerName
	}
	if moduleAddr != "" {
		r.Metadata["terraform_module"] = moduleAddr
	}
}

func (p *TerraformParser) parseConfig(path string, data []byte) ([]*models.Resource, error) {
	var doc tfConfigDocument
	if err := decodeJSONStrict(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid terraform config json: %w", err)
	}
	var out []*models.Resource
	for _, typ := range sortedKeys(doc.Resource) {
		for _, name := range sortedKeys(doc.Resource[typ]) {
			props, ok := doc.Resource[typ][name].(map[string]any)
			if !ok {
				props = map[string]any{}
			}
			r, err := models.NewResource(typ+"."+name, typ, name, string(models.ResourceTypeTerraform), props)
			if err != nil {
				return nil, err
			}
			r.Metadata["file"] = path
			r.Metadata["terraform_config"] = "true"
			out = append(out, r)
		}
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
