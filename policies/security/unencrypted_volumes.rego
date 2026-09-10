package iac_sentinel.security.unencrypted_volumes

import rego.v1

# Deny unencrypted standalone EBS volumes
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_ebs_volume"
    not resource.change.after.encrypted == true

    msg := {
        "rule": "unencrypted_volumes",
        "category": "security",
        "severity": "medium",
        "resource": resource.address,
        "message": sprintf("EBS volume %s is not encrypted at rest", [resource.address]),
    }
}

# Deny unencrypted root block devices on EC2 instances
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    some root_device in resource.change.after.root_block_device
    not root_device.encrypted == true

    msg := {
        "rule": "unencrypted_volumes",
        "category": "security",
        "severity": "medium",
        "resource": resource.address,
        "message": sprintf("EC2 instance %s has an unencrypted root block device", [resource.address]),
    }
}

# Deny unencrypted attached EBS block devices on EC2 instances
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    some ebs_device in resource.change.after.ebs_block_device
    not ebs_device.encrypted == true

    msg := {
        "rule": "unencrypted_volumes",
        "category": "security",
        "severity": "medium",
        "resource": resource.address,
        "message": sprintf("EC2 instance %s has an unencrypted attached EBS block device (%s)", [resource.address, ebs_device.device_name]),
    }
}
