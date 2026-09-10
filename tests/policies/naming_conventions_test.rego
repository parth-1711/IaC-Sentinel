package iac_sentinel.governance.naming_conventions_test

import rego.v1
import data.iac_sentinel.governance.naming_conventions.deny

test_deny_uppercase_bucket if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.bad_bucket",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "MyCompany-Reports-Bucket"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "low"
}

test_deny_underscore_bucket if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.bad_bucket",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "my_company_reports"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "low"
}

test_allow_valid_bucket if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.valid_bucket",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "my-company-reports-prod"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_deny_sg_with_spaces_or_uppercase if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group.bad_sg",
                "type": "aws_security_group",
                "change": {
                    "after": {
                        "name": "Web SG Production"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "low"
}

test_allow_valid_sg_name if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_security_group.good_sg",
                "type": "aws_security_group",
                "change": {
                    "after": {
                        "name": "web-sg-production"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
