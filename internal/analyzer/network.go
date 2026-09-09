package analyzer

import (
	"fmt"
	"math"

	"github.com/precept/precept/internal/models"
)

// Network rule identifiers.
const (
	RuleNetPublicSSH    = "NET-001"
	RuleNetPublicRDP    = "NET-002"
	RuleNetPublicDB     = "NET-003"
	RuleNetPublicHTTP   = "NET-004"
	RuleNetPublicSubnet = "NET-005"
)

var (
	ruleNetPublicSSH = rule{
		ID: RuleNetPublicSSH, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "SSH port 22 is reachable from the public internet",
		Remediation: "Restrict SSH ingress to trusted CIDR ranges or use a bastion with SSM Session Manager",
	}
	ruleNetPublicRDP = rule{
		ID: RuleNetPublicRDP, Severity: models.SeverityCritical, BaseScore: 95,
		Description: "RDP port 3389 is reachable from the public internet",
		Remediation: "Restrict RDP ingress to trusted CIDR ranges or use a session gateway",
	}
	ruleNetPublicDB = rule{
		ID: RuleNetPublicDB, Severity: models.SeverityCritical, BaseScore: 90,
		Description: "Database port is reachable from the public internet",
		Remediation: "Place databases in private subnets and restrict ingress to application security groups",
	}
	ruleNetPublicHTTP = rule{
		ID: RuleNetPublicHTTP, Severity: models.SeverityMedium, BaseScore: 50,
		Description: "Web port is reachable from the public internet",
		Remediation: "Terminate public web traffic at a load balancer instead of the instance security group",
	}
	ruleNetPublicSubnet = rule{
		ID: RuleNetPublicSubnet, Severity: models.SeverityHigh, BaseScore: 75,
		Description: "Subnet assigns public IPs on launch",
		Remediation: "Set map_public_ip_on_launch to false unless the subnet is a designated public tier",
	}
)

var publicCIDRs = map[string]bool{"0.0.0.0/0": true, "::/0": true}

// sensitivePorts maps ports to the rules they trigger.
var sensitivePorts = []struct {
	port int
	r    rule
}{
	{22, ruleNetPublicSSH},
	{3389, ruleNetPublicRDP},
	{3306, ruleNetPublicDB},
	{5432, ruleNetPublicDB},
	{80, ruleNetPublicHTTP},
	{443, ruleNetPublicHTTP},
}

// NetworkAnalyzer detects public exposure in Terraform security groups
// and public subnets.
type NetworkAnalyzer struct{}

// NewNetworkAnalyzer returns a network analyzer.
func NewNetworkAnalyzer() *NetworkAnalyzer { return &NetworkAnalyzer{} }

// Name identifies the analyzer in logs and diagnostics.
func (a *NetworkAnalyzer) Name() string { return "network" }

// SupportedProviders lists the providers this analyzer consumes.
func (a *NetworkAnalyzer) SupportedProviders() []models.ResourceType {
	return []models.ResourceType{models.ResourceTypeTerraform}
}

// Analyze runs every network rule against one resource.
func (a *NetworkAnalyzer) Analyze(resource *models.Resource) []*models.Finding {
	switch resource.Type {
	case "aws_security_group":
		return a.analyzeSecurityGroup(resource)
	case "aws_security_group_rule":
		return a.analyzeSecurityGroupRule(resource)
	case "aws_subnet":
		return a.analyzeSubnet(resource)
	default:
		return nil
	}
}

func (a *NetworkAnalyzer) analyzeSecurityGroup(resource *models.Resource) []*models.Finding {
	var findings []*models.Finding
	for _, direction := range []string{"ingress", "egress"} {
		entries, ok := resource.Properties[direction].([]any)
		if !ok {
			continue
		}
		for i, entry := range entries {
			rules, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			findings = append(findings, checkExposure(resource.ID, fmt.Sprintf("%s rule %d", direction, i), rules)...)
		}
	}
	return findings
}

func (a *NetworkAnalyzer) analyzeSecurityGroupRule(resource *models.Resource) []*models.Finding {
	ruleType, _ := resource.Properties["type"].(string)
	if ruleType != "ingress" && ruleType != "egress" {
		return nil
	}
	return checkExposure(resource.ID, ruleType+" rule", resource.Properties)
}

// checkExposure matches one rule entry's CIDR blocks against its port
// range. An entry exposes a sensitive port when it is open to the world
// and from_port <= port <= to_port, so an all-ports entry trips every
// port rule.
func checkExposure(resourceID, label string, entry map[string]any) []*models.Finding {
	if !isPublicEntry(entry) {
		return nil
	}
	from := portValue(entry["from_port"])
	to := portValue(entry["to_port"])
	if from < 0 || to < 0 {
		return nil
	}
	var findings []*models.Finding
	fired := map[string]bool{}
	for _, sp := range sensitivePorts {
		if sp.port >= from && sp.port <= to && !fired[sp.r.ID] {
			fired[sp.r.ID] = true
			findings = append(findings, newFinding(sp.r, resourceID, "%s (%d)", label, sp.port))
		}
	}
	return findings
}

func isPublicEntry(entry map[string]any) bool {
	for _, field := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		for _, cidr := range stringsList(entry[field]) {
			if publicCIDRs[cidr] {
				return true
			}
		}
	}
	return false
}

// portValue extracts a port number from decoded JSON. Terraform JSON
// numbers decode as float64; anything else is treated as unknown.
func portValue(v any) int {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 65535 {
			return -1
		}
		return int(n)
	case int:
		if n < 0 || n > 65535 {
			return -1
		}
		return n
	default:
		return -1
	}
}

func (a *NetworkAnalyzer) analyzeSubnet(resource *models.Resource) []*models.Finding {
	public, ok := resource.Properties["map_public_ip_on_launch"].(bool)
	if !ok || !public {
		return nil
	}
	return []*models.Finding{newFinding(ruleNetPublicSubnet, resource.ID)}
}
