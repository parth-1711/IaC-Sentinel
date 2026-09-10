package iac_sentinel.security.unencrypted_volumes_test

import rego.v1
import data.iac_sentinel.security.unencrypted_volumes.deny

test_deny_unencrypted_ebs_volume if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_ebs_volume.app_data",
                "type": "aws_ebs_volume",
                "change": {
                    "after": {
                        "size": 100,
                        "encrypted": false
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
    violations[_].severity == "medium"
}

test_allow_encrypted_ebs_volume if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_ebs_volume.app_data",
                "type": "aws_ebs_volume",
                "change": {
                    "after": {
                        "size": 100,
                        "encrypted": true
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}

test_deny_unencrypted_instance_root_device if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.medium",
                        "root_block_device": [
                            {
                                "volume_size": 20,
                                "encrypted": false
                            }
                        ]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 1
}

test_allow_encrypted_instance_root_device if {
    mock_input := {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "after": {
                        "instance_type": "t3.medium",
                        "root_block_device": [
                            {
                                "volume_size": 20,
                                "encrypted": true
                            }
                        ]
                    }
                }
            }
        ]
    }
    violations := deny with input as mock_input
    count(violations) == 0
}
