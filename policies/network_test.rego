package precept.authz

import data.precept.authz.deny

open_ssh := {
	"id": "aws_security_group.open", "type": "aws_security_group", "name": "open", "provider": "terraform",
	"properties": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
}

test_net_001_ssh_open if {
	some f in deny with input as open_ssh
	f.rule_id == "NET-001"
	f.severity == "CRITICAL"
}

test_net_001_absent_for_private_cidr if {
	priv := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]},
	}
	not "NET-001" in {f.rule_id | some f in deny with input as priv}
}

test_net_001_absent_when_port_outside_range if {
	other := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}]},
	}
	not "NET-001" in {f.rule_id | some f in deny with input as other}
}

test_net_002_rdp_open if {
	rdp := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"from_port": 3389, "to_port": 3389, "ipv6_cidr_blocks": ["::/0"]}]},
	}
	some f in deny with input as rdp
	f.rule_id == "NET-002"
}

test_net_003_mysql_open if {
	db := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"egress": [{"from_port": 3306, "to_port": 3306, "cidr_blocks": ["0.0.0.0/0"]}]},
	}
	some f in deny with input as db
	f.rule_id == "NET-003"
}

test_net_003_postgres_in_range if {
	db := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}]},
	}
	some f in deny with input as db
	f.rule_id == "NET-003"
}

test_net_004_http_open if {
	web := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"from_port": 80, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]},
	}
	ids := {f.rule_id | some f in deny with input as web}
	ids["NET-004"]
	not ids["NET-001"]
}

test_net_001_sg_rule if {
	rule := {
		"id": "aws_security_group_rule.s", "type": "aws_security_group_rule", "name": "s", "provider": "terraform",
		"properties": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
	}
	some f in deny with input as rule
	f.rule_id == "NET-001"
}

test_net_sg_rule_wrong_type_ignored if {
	rule := {
		"id": "aws_security_group_rule.s", "type": "aws_security_group_rule", "name": "s", "provider": "terraform",
		"properties": {"type": "other", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
	}
	count([f | some f in deny with input as rule]) == 0
}

test_net_005_public_subnet if {
	sub := {
		"id": "aws_subnet.p", "type": "aws_subnet", "name": "p", "provider": "terraform",
		"properties": {"map_public_ip_on_launch": true},
	}
	some f in deny with input as sub
	f.rule_id == "NET-005"
	f.severity == "HIGH"
}

test_net_005_private_subnet_clean if {
	sub := {
		"id": "aws_subnet.p", "type": "aws_subnet", "name": "p", "provider": "terraform",
		"properties": {"map_public_ip_on_launch": false},
	}
	count([f | some f in deny with input as sub]) == 0
}

test_net_missing_ports_no_findings if {
	sg := {
		"id": "sg", "type": "aws_security_group", "name": "s", "provider": "terraform",
		"properties": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
	}
	count([f | some f in deny with input as sg]) == 0
}
