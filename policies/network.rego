package precept.authz

public_cidrs := {"0.0.0.0/0", "::/0"}

public_entry(entry) if {
	some field in ["cidr_blocks", "ipv6_cidr_blocks"]
	some cidr in as_array(entry[field])
	public_cidrs[cidr]
}

port_exposed(entry, port) if {
	public_entry(entry)
	entry.from_port <= port
	port <= entry.to_port
}

deny contains {
	"rule_id": "NET-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "SSH port 22 is reachable from the public internet",
	"remediation": "Restrict SSH ingress to trusted CIDR ranges or use a bastion with SSM Session Manager",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group"
	some dir in ["ingress", "egress"]
	some entry in as_array(input.properties[dir])
	port_exposed(entry, 22)
}

deny contains {
	"rule_id": "NET-001",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "SSH port 22 is reachable from the public internet",
	"remediation": "Restrict SSH ingress to trusted CIDR ranges or use a bastion with SSM Session Manager",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group_rule"
	input.properties.type in ["ingress", "egress"]
	port_exposed(input.properties, 22)
}

deny contains {
	"rule_id": "NET-002",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "RDP port 3389 is reachable from the public internet",
	"remediation": "Restrict RDP ingress to trusted CIDR ranges or use a session gateway",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group"
	some dir in ["ingress", "egress"]
	some entry in as_array(input.properties[dir])
	port_exposed(entry, 3389)
}

deny contains {
	"rule_id": "NET-002",
	"severity": "CRITICAL",
	"score": 95,
	"resource": input.id,
	"description": "RDP port 3389 is reachable from the public internet",
	"remediation": "Restrict RDP ingress to trusted CIDR ranges or use a session gateway",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group_rule"
	input.properties.type in ["ingress", "egress"]
	port_exposed(input.properties, 3389)
}

deny contains {
	"rule_id": "NET-003",
	"severity": "CRITICAL",
	"score": 90,
	"resource": input.id,
	"description": "Database port is reachable from the public internet",
	"remediation": "Place databases in private subnets and restrict ingress to application security groups",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group"
	some dir in ["ingress", "egress"]
	some entry in as_array(input.properties[dir])
	some port in [3306, 5432]
	port_exposed(entry, port)
}

deny contains {
	"rule_id": "NET-003",
	"severity": "CRITICAL",
	"score": 90,
	"resource": input.id,
	"description": "Database port is reachable from the public internet",
	"remediation": "Place databases in private subnets and restrict ingress to application security groups",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group_rule"
	input.properties.type in ["ingress", "egress"]
	some port in [3306, 5432]
	port_exposed(input.properties, port)
}

deny contains {
	"rule_id": "NET-004",
	"severity": "MEDIUM",
	"score": 50,
	"resource": input.id,
	"description": "Web port is reachable from the public internet",
	"remediation": "Terminate public web traffic at a load balancer instead of the instance security group",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group"
	some dir in ["ingress", "egress"]
	some entry in as_array(input.properties[dir])
	some port in [80, 443]
	port_exposed(entry, port)
}

deny contains {
	"rule_id": "NET-004",
	"severity": "MEDIUM",
	"score": 50,
	"resource": input.id,
	"description": "Web port is reachable from the public internet",
	"remediation": "Terminate public web traffic at a load balancer instead of the instance security group",
} if {
	input.provider == "terraform"
	input.type == "aws_security_group_rule"
	input.properties.type in ["ingress", "egress"]
	some port in [80, 443]
	port_exposed(input.properties, port)
}

deny contains {
	"rule_id": "NET-005",
	"severity": "HIGH",
	"score": 75,
	"resource": input.id,
	"description": "Subnet assigns public IPs on launch",
	"remediation": "Set map_public_ip_on_launch to false unless the subnet is a designated public tier",
} if {
	input.provider == "terraform"
	input.type == "aws_subnet"
	input.properties.map_public_ip_on_launch == true
}
