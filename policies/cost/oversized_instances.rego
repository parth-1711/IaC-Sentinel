package iac_sentinel.cost.oversized_instances

import rego.v1

disallowed_size_suffixes := {
    "2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge", "24xlarge", "32xlarge", "metal"
}

# Deny EC2 instances provisioned with oversized / expensive instance types
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type

    is_oversized(instance_type)

    msg := {
        "rule": "oversized_instances",
        "category": "cost",
        "severity": "medium",
        "resource": resource.address,
        "message": sprintf("EC2 instance %s is provisioned with oversized instance type '%s' exceeding cost budget limits", [resource.address, instance_type]),
    }
}

is_oversized(instance_type) if {
    some suffix in disallowed_size_suffixes
    endswith(instance_type, suffix)
}
