package iac_sentinel.governance.naming_conventions

import rego.v1

# Deny S3 buckets with uppercase characters or underscores
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    bucket_name := resource.change.after.bucket

    regex.match("[A-Z_]", bucket_name)

    msg := {
        "rule": "naming_conventions",
        "category": "governance",
        "severity": "low",
        "resource": resource.address,
        "message": sprintf("S3 bucket name '%s' violates naming conventions (must use lowercase letters, numbers, and hyphens only)", [bucket_name]),
    }
}

# Deny security group names with uppercase or spaces
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    sg_name := resource.change.after.name

    regex.match("[\\sA-Z]", sg_name)

    msg := {
        "rule": "naming_conventions",
        "category": "governance",
        "severity": "low",
        "resource": resource.address,
        "message": sprintf("Security group name '%s' violates naming conventions (must be lowercase kebab-case without spaces or uppercase letters)", [sg_name]),
    }
}
