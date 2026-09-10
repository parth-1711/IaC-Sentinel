package iac_sentinel.security.open_security_groups

import rego.v1

# Allowed public ports (e.g., standard HTTP and HTTPS)
allowed_public_ports := {80, 443}

# Deny standalone aws_security_group_rule resources allowing 0.0.0.0/0 on sensitive ports
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    "0.0.0.0/0" in resource.change.after.cidr_blocks
    port := resource.change.after.from_port

    not port in allowed_public_ports

    msg := {
        "rule": "open_security_groups",
        "category": "security",
        "severity": "high",
        "resource": resource.address,
        "message": sprintf("Security group rule %s allows ingress from 0.0.0.0/0 on non-standard port %d", [resource.address, port]),
    }
}

# Deny inline ingress blocks on aws_security_group resources allowing 0.0.0.0/0
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    some ingress in resource.change.after.ingress
    "0.0.0.0/0" in ingress.cidr_blocks
    port := ingress.from_port

    not port in allowed_public_ports

    msg := {
        "rule": "open_security_groups",
        "category": "security",
        "severity": "high",
        "resource": resource.address,
        "message": sprintf("Security group %s contains inline ingress allowing 0.0.0.0/0 on non-standard port %d", [resource.address, port]),
    }
}
