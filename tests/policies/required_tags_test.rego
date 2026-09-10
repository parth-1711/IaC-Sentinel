package iac_sentinel.governance.required_tags_test

import rego.v1
import data.iac_sentinel.governance.required_tags.deny

test_deny_instance_missing_tags if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.backend",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.small",
                        "tags": {
                            "Environment": "production"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "medium"
}

test_deny_bucket_without_tags_block if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.media",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "company-media-prod"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "medium"
}

test_allow_resource_with_all_tags if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.backend",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.small",
                        "tags": {
                            "Environment": "production",
                            "Owner": "platform-team",
                            "Project": "sentinel"
                        }
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
