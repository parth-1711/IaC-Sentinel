package iac_sentinel.cost.missing_auto_shutdown_tags_test

import rego.v1
import data.iac_sentinel.cost.missing_auto_shutdown_tags.deny

test_deny_dev_instance_without_shutdown_tag if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.dev_worker",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.medium",
                        "tags": {
                            "Environment": "dev",
                            "Owner": "engineering"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "low"
}

test_allow_dev_instance_with_autoshutdown if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.dev_worker",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.medium",
                        "tags": {
                            "Environment": "dev",
                            "AutoShutdown": "true"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_allow_dev_instance_with_schedule if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.dev_worker",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.medium",
                        "tags": {
                            "Environment": "staging",
                            "Schedule": "weekdays-9to5"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_allow_prod_instance_without_autoshutdown if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.prod_api",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.large",
                        "tags": {
                            "Environment": "production"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
