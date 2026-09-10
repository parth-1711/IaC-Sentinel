package iac_sentinel.cost.missing_auto_shutdown_tags

import rego.v1

non_prod_environments := {"dev", "development", "staging", "test", "sandbox", "qa"}

target_resource_types := {"aws_instance", "aws_db_instance"}

# Deny non-production compute/database instances lacking AutoShutdown or Schedule tags
deny contains msg if {
    some resource in input.resource_changes
    resource.type in target_resource_types
    tags := resource.change.after.tags
    env := lower(tags.Environment)
    env in non_prod_environments

    not has_shutdown_tag(tags)

    msg := {
        "rule": "missing_auto_shutdown_tags",
        "category": "cost",
        "severity": "low",
        "resource": resource.address,
        "message": sprintf("Non-production resource %s in environment '%s' is missing 'AutoShutdown' or 'Schedule' tag to curtail idle run spend", [resource.address, env]),
    }
}

has_shutdown_tag(tags) if {
    tags.AutoShutdown != ""
    tags.AutoShutdown != null
}

has_shutdown_tag(tags) if {
    tags.Schedule != ""
    tags.Schedule != null
}
