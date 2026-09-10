package iac_sentinel.security.open_security_groups_test

import rego.v1
import data.iac_sentinel.security.open_security_groups.deny

test_deny_open_ssh_port if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group_rule.ssh",
                "type": "aws_security_group_rule",
                "change": {
                    "after": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "high"
}

test_allow_public_https if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group_rule.https",
                "type": "aws_security_group_rule",
                "change": {
                    "after": {
                        "type": "ingress",
                        "from_port": 443,
                        "to_port": 443,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_allow_private_ssh if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group_rule.internal_ssh",
                "type": "aws_security_group_rule",
                "change": {
                    "after": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/16"]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_deny_inline_rdp_port if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group.windows_sg",
                "type": "aws_security_group",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 3389,
                                "to_port": 3389,
                                "cidr_blocks": ["0.0.0.0/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
}
