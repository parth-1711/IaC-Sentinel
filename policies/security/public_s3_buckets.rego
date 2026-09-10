package iac_sentinel.security.public_s3_buckets

import rego.v1

public_acls := {"public-read", "public-read-write", "authenticated-read"}

# Deny S3 bucket with public ACL
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    acl := resource.change.after.acl
    acl in public_acls

    msg := {
        "rule": "public_s3_buckets",
        "category": "security",
        "severity": "high",
        "resource": resource.address,
        "message": sprintf("S3 bucket %s configured with dangerous public ACL '%s'", [resource.address, acl]),
    }
}

# Deny standalone S3 bucket ACL resource with public ACL
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_acl"
    acl := resource.change.after.acl
    acl in public_acls

    msg := {
        "rule": "public_s3_buckets",
        "category": "security",
        "severity": "high",
        "resource": resource.address,
        "message": sprintf("S3 bucket ACL %s grants public access via ACL '%s'", [resource.address, acl]),
    }
}

# Deny S3 public access block with any disabling of public protection
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    after := resource.change.after

    is_public_access_allowed(after)

    msg := {
        "rule": "public_s3_buckets",
        "category": "security",
        "severity": "high",
        "resource": resource.address,
        "message": sprintf("S3 bucket public access block %s does not fully block public access", [resource.address]),
    }
}

is_public_access_allowed(block) if {
    block.block_public_acls == false
}

is_public_access_allowed(block) if {
    block.block_public_policy == false
}

is_public_access_allowed(block) if {
    block.ignore_public_acls == false
}

is_public_access_allowed(block) if {
    block.restrict_public_buckets == false
}
