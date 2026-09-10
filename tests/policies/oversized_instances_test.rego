package iac_sentinel.cost.oversized_instances_test

import rego.v1
import data.iac_sentinel.cost.oversized_instances.deny

test_deny_oversized_4xlarge if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.analytics",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "m5.4xlarge"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "medium"
}

test_deny_oversized_metal if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.db",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "i3.metal"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
}

test_allow_standard_instance if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.large"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
