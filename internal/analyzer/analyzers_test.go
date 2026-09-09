package analyzer

import (
	"testing"

	"github.com/precept/precept/internal/models"
)

func tfResource(t *testing.T, resourceType string, props map[string]any) *models.Resource {
	t.Helper()
	r, err := models.NewResource(resourceType+".test", resourceType, "test", "terraform", props)
	if err != nil {
		t.Fatalf("NewResource error: %v", err)
	}
	return r
}

func TestNetworkPublicSSH(t *testing.T) {
	t.Parallel()
	res := tfResource(t, "aws_security_group", map[string]any{
		"ingress": []any{
			map[string]any{"from_port": float64(22), "to_port": float64(22), "cidr_blocks": []any{"0.0.0.0/0"}},
		},
	})
	findings := NewNetworkAnalyzer().Analyze(res)
	if len(findings) != 1 || findings[0].RuleID != RuleNetPublicSSH {
		t.Fatalf("findings = %v, want NET-001", ruleIDs(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL", findings[0].Severity)
	}
	if findings[0].Description == "" || findings[0].Remediation == "" {
		t.Error("finding missing description or remediation")
	}
}

func TestNetworkPortRangesAndIPv6(t *testing.T) {
	t.Parallel()
	res := tfResource(t, "aws_security_group", map[string]any{
		"ingress": []any{
			map[string]any{"from_port": float64(0), "to_port": float64(65535), "cidr_blocks": []any{"10.0.0.0/8"}, "ipv6_cidr_blocks": []any{"::/0"}},
		},
	})
	findings := NewNetworkAnalyzer().Analyze(res)
	got := ruleIDs(findings)
	want := []string{RuleNetPublicSSH, RuleNetPublicRDP, RuleNetPublicDB, RuleNetPublicHTTP}
	if len(got) != len(want) {
		t.Fatalf("rules = %v, want %v (all-ports entry trips every rule)", got, want)
	}
	for i, r := range want {
		if got[i] != r {
			t.Errorf("rules[%d] = %q, want %q", i, got[i], r)
		}
	}
}

func TestNetworkWebPortsMedium(t *testing.T) {
	t.Parallel()
	res := tfResource(t, "aws_security_group", map[string]any{
		"ingress": []any{
			map[string]any{"from_port": float64(443), "to_port": float64(443), "cidr_blocks": []any{"0.0.0.0/0"}},
		},
	})
	findings := NewNetworkAnalyzer().Analyze(res)
	if len(findings) != 1 || findings[0].RuleID != RuleNetPublicHTTP {
		t.Fatalf("findings = %v, want NET-004", ruleIDs(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want MEDIUM", findings[0].Severity)
	}
}

func TestNetworkDatabasePorts(t *testing.T) {
	t.Parallel()
	for _, port := range []float64{3306, 5432} {
		res := tfResource(t, "aws_security_group", map[string]any{
			"ingress": []any{map[string]any{"from_port": port, "to_port": port, "cidr_blocks": []any{"0.0.0.0/0"}}},
		})
		findings := NewNetworkAnalyzer().Analyze(res)
		if len(findings) != 1 || findings[0].RuleID != RuleNetPublicDB {
			t.Errorf("port %.0f: findings = %v, want NET-003", port, ruleIDs(findings))
		}
	}
}

func TestNetworkPrivateCIDRNoFindings(t *testing.T) {
	t.Parallel()
	res := tfResource(t, "aws_security_group", map[string]any{
		"ingress": []any{
			map[string]any{"from_port": float64(22), "to_port": float64(22), "cidr_blocks": []any{"10.0.0.0/16"}},
		},
	})
	if findings := NewNetworkAnalyzer().Analyze(res); len(findings) != 0 {
		t.Errorf("private CIDR produced %v, want none", ruleIDs(findings))
	}
}

func TestNetworkSecurityGroupRuleResource(t *testing.T) {
	t.Parallel()
	open := tfResource(t, "aws_security_group_rule", map[string]any{
		"type": "ingress", "from_port": float64(3389), "to_port": float64(3389), "cidr_blocks": []any{"0.0.0.0/0"},
	})
	findings := NewNetworkAnalyzer().Analyze(open)
	if len(findings) != 1 || findings[0].RuleID != RuleNetPublicRDP {
		t.Fatalf("findings = %v, want NET-002", ruleIDs(findings))
	}
	egress := tfResource(t, "aws_security_group_rule", map[string]any{
		"type": "egress", "from_port": float64(22), "to_port": float64(22), "cidr_blocks": []any{"0.0.0.0/0"},
	})
	if findings := NewNetworkAnalyzer().Analyze(egress); len(findings) != 1 || findings[0].RuleID != RuleNetPublicSSH {
		t.Errorf("egress findings = %v, want NET-001", ruleIDs(findings))
	}
	untyped := tfResource(t, "aws_security_group_rule", map[string]any{
		"from_port": float64(22), "to_port": float64(22), "cidr_blocks": []any{"0.0.0.0/0"},
	})
	if findings := NewNetworkAnalyzer().Analyze(untyped); len(findings) != 0 {
		t.Errorf("rule without type produced %v, want none (direction unknown)", ruleIDs(findings))
	}
}

func TestNetworkPublicSubnet(t *testing.T) {
	t.Parallel()
	public := tfResource(t, "aws_subnet", map[string]any{"map_public_ip_on_launch": true})
	findings := NewNetworkAnalyzer().Analyze(public)
	if len(findings) != 1 || findings[0].RuleID != RuleNetPublicSubnet {
		t.Fatalf("findings = %v, want NET-005", ruleIDs(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", findings[0].Severity)
	}
	private := tfResource(t, "aws_subnet", map[string]any{"map_public_ip_on_launch": false})
	if findings := NewNetworkAnalyzer().Analyze(private); len(findings) != 0 {
		t.Errorf("private subnet produced %v, want none", ruleIDs(findings))
	}
	absent := tfResource(t, "aws_subnet", nil)
	if findings := NewNetworkAnalyzer().Analyze(absent); len(findings) != 0 {
		t.Errorf("subnet without the flag produced %v, want none", ruleIDs(findings))
	}
}

func TestNetworkMalformedEntries(t *testing.T) {
	t.Parallel()
	analyzer := NewNetworkAnalyzer()
	tests := []struct {
		name        string
		resourceTyp string
		props       map[string]any
	}{
		{name: "ingress not a list", resourceTyp: "aws_security_group", props: map[string]any{"ingress": "oops"}},
		{name: "entry not a map", resourceTyp: "aws_security_group", props: map[string]any{"ingress": []any{42}}},
		{name: "missing ports", resourceTyp: "aws_security_group", props: map[string]any{"ingress": []any{map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}}}}},
		{name: "port out of range", resourceTyp: "aws_security_group", props: map[string]any{"ingress": []any{map[string]any{"from_port": float64(99999), "to_port": float64(99999), "cidr_blocks": []any{"0.0.0.0/0"}}}}},
		{name: "nil properties", resourceTyp: "aws_security_group", props: nil},
		{name: "unsupported type", resourceTyp: "aws_vpc", props: map[string]any{"cidr_block": "10.0.0.0/16"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := analyzer.Analyze(tfResource(t, tt.resourceTyp, tt.props))
			for _, f := range findings {
				if f == nil {
					t.Error("analyzer emitted nil finding on malformed input")
				}
			}
		})
	}
}

func TestStoragePublicBucket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		props map[string]any
	}{
		{name: "publicly accessible flag", props: map[string]any{"publicly_accessible": true}},
		{name: "public acl", props: map[string]any{"acl": "public-read"}},
		{name: "authenticated acl", props: map[string]any{"acl": "authenticated-read"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := NewStorageAnalyzer().Analyze(tfResource(t, "aws_s3_bucket", tt.props))
			if !containsString(ruleIDs(findings), RuleStoPublicBucket) {
				t.Errorf("rules = %v, want %s", ruleIDs(findings), RuleStoPublicBucket)
			}
		})
	}
}

func TestStorageBucketFindings(t *testing.T) {
	t.Parallel()
	clean := tfResource(t, "aws_s3_bucket", map[string]any{
		"acl":                                  "private",
		"server_side_encryption_configuration": map[string]any{"rule": map[string]any{}},
		"logging":                              map[string]any{"target_bucket": "logs"},
	})
	if findings := NewStorageAnalyzer().Analyze(clean); len(findings) != 0 {
		t.Errorf("clean bucket produced %v, want none", ruleIDs(findings))
	}
	bare := tfResource(t, "aws_s3_bucket", map[string]any{"bucket": "x"})
	findings := NewStorageAnalyzer().Analyze(bare)
	got := ruleIDs(findings)
	if len(got) != 2 || got[0] != RuleStoMissingEncryption || got[1] != RuleStoMissingLogging {
		t.Errorf("bare bucket produced %v, want STO-002 and STO-003", got)
	}
}

func TestStorageAccessBlock(t *testing.T) {
	t.Parallel()
	open := tfResource(t, "aws_s3_bucket_public_access_block", map[string]any{
		"block_public_acls": true, "block_public_policy": false, "ignore_public_acls": true, "restrict_public_buckets": true,
	})
	findings := NewStorageAnalyzer().Analyze(open)
	if len(findings) != 1 || findings[0].RuleID != RuleStoPublicBucket {
		t.Fatalf("findings = %v, want STO-001", ruleIDs(findings))
	}
	blocked := tfResource(t, "aws_s3_bucket_public_access_block", map[string]any{
		"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true,
	})
	if findings := NewStorageAnalyzer().Analyze(blocked); len(findings) != 0 {
		t.Errorf("fully blocked bucket produced %v, want none", ruleIDs(findings))
	}
	partial := tfResource(t, "aws_s3_bucket_public_access_block", map[string]any{
		"block_public_acls": true,
	})
	if findings := NewStorageAnalyzer().Analyze(partial); len(findings) != 0 {
		t.Errorf("absent flags treated as false, produced %v; absent flags are unknown, not open", ruleIDs(findings))
	}
}

func TestStorageUnsupportedType(t *testing.T) {
	t.Parallel()
	if findings := NewStorageAnalyzer().Analyze(tfResource(t, "aws_dynamodb_table", nil)); len(findings) != 0 {
		t.Errorf("dynamodb table produced %v, want none", ruleIDs(findings))
	}
}

func TestLoggingLogGroup(t *testing.T) {
	t.Parallel()
	short := tfResource(t, "aws_cloudwatch_log_group", map[string]any{"retention_in_days": float64(7)})
	findings := NewLoggingAnalyzer().Analyze(short)
	if len(findings) != 2 || findings[0].RuleID != RuleLogShortRetain || findings[1].RuleID != RuleLogMissingKMS {
		t.Fatalf("findings = %v, want LOG-002 and LOG-003", ruleIDs(findings))
	}
	infinite := tfResource(t, "aws_cloudwatch_log_group", map[string]any{"kms_key_id": "arn:aws:kms:...:key/abc"})
	if findings := NewLoggingAnalyzer().Analyze(infinite); len(findings) != 0 {
		t.Errorf("log group without retention (never expires) produced %v, want none", ruleIDs(findings))
	}
	boundary := tfResource(t, "aws_cloudwatch_log_group", map[string]any{"retention_in_days": float64(365)})
	if findings := NewLoggingAnalyzer().Analyze(boundary); !containsString(ruleIDs(findings), RuleLogMissingKMS) || containsString(ruleIDs(findings), RuleLogShortRetain) {
		t.Errorf("365-day retention findings = %v, want LOG-003 only", ruleIDs(findings))
	}
}

func TestLoggingTrail(t *testing.T) {
	t.Parallel()
	trail := tfResource(t, "aws_cloudtrail", map[string]any{"is_multi_region_trail": true})
	findings := NewLoggingAnalyzer().Analyze(trail)
	if len(findings) != 1 || findings[0].RuleID != RuleLogMissingKMS {
		t.Fatalf("findings = %v, want LOG-003", ruleIDs(findings))
	}
	encrypted := tfResource(t, "aws_cloudtrail", map[string]any{"kms_key_id": "arn:aws:kms:...:key/abc"})
	if findings := NewLoggingAnalyzer().Analyze(encrypted); len(findings) != 0 {
		t.Errorf("encrypted trail produced %v, want none", ruleIDs(findings))
	}
}

func TestLoggingBatchNoTrail(t *testing.T) {
	t.Parallel()
	analyzer := NewLoggingAnalyzer()
	resources := []*models.Resource{
		tfResource(t, "aws_s3_bucket", nil),
		tfResource(t, "aws_subnet", nil),
	}
	findings := analyzer.AnalyzeBatch(resources)
	if len(findings) != 1 || findings[0].RuleID != RuleLogMissingTrail {
		t.Fatalf("findings = %v, want LOG-001", ruleIDs(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", findings[0].Severity)
	}
	withTrail := []*models.Resource{tfResource(t, "aws_s3_bucket", nil), tfResource(t, "aws_cloudtrail", nil)}
	if findings := analyzer.AnalyzeBatch(withTrail); len(findings) != 0 {
		t.Errorf("corpus with trail produced %v, want none", ruleIDs(findings))
	}
	if findings := analyzer.AnalyzeBatch(nil); len(findings) != 0 {
		t.Errorf("empty corpus produced %v, want none", ruleIDs(findings))
	}
}
