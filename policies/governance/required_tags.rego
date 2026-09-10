package iac_sentinel.governance.required_tags

import rego.v1

mandatory_tags := {"Environment", "Owner", "Project"}

taggable_resource_types := {
    "aws_instance",
    "aws_s3_bucket",
    "aws_ebs_volume",
    "aws_security_group",
    "aws_vpc",
    "aws_subnet"
}

# Deny taggable cloud resources that fail to include mandatory governance tags
deny contains msg if {
    some resource in input.resource_changes
    resource.type in taggable_resource_types
    tags := object.get(resource.change.after, "tags", {})

    missing := [tag | some tag in mandatory_tags; not has_tag(tags, tag)]
    count(missing) > 0

    msg := {
        "rule": "required_tags",
        "category": "governance",
        "severity": "medium",
        "resource": resource.address,
        "message": sprintf("Resource %s is missing mandatory governance tags: %v", [resource.address, missing]),
    }
}

has_tag(tags, key) if {
    tags[key] != null
    tags[key] != ""
}
