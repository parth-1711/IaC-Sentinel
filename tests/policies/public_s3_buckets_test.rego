package iac_sentinel.security.public_s3_buckets_test

import rego.v1
import data.iac_sentinel.security.public_s3_buckets.deny

test_deny_bucket_with_public_read_acl if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.data_lake",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "company-data-lake",
                        "acl": "public-read"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "high"
}

test_allow_bucket_with_private_acl if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.data_lake",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "company-data-lake",
                        "acl": "private"
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_deny_unblocked_public_access_block if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket_public_access_block.bad_block",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "after": {
                        "block_public_acls": true,
                        "block_public_policy": false,
                        "ignore_public_acls": true,
                        "restrict_public_buckets": true
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
}

test_allow_strict_public_access_block if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_s3_bucket_public_access_block.strict_block",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "after": {
                        "block_public_acls": true,
                        "block_public_policy": true,
                        "ignore_public_acls": true,
                        "restrict_public_buckets": true
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
