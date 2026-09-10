"""Unit tests for remediation patch generation and HCL diffing."""

from __future__ import annotations
from pathlib import Path
from scanner.parse_violations import Violation
from agent.remediate import (
    find_and_replace_hcl_resource,
    create_unified_diff,
    generate_patch_for_violation,
)
from agent.llm_client import GeminiClient


def test_find_and_replace_hcl_resource():
    original_hcl = (
        'provider "aws" {\n  region = "us-east-1"\n}\n\n'
        'resource "aws_security_group_rule" "ingress_ssh" {\n'
        '  type = "ingress"\n'
        '  from_port = 22\n'
        '  to_port = 22\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n\n'
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "my-bucket"\n'
        '}\n'
    )

    replacement = (
        'resource "aws_security_group_rule" "ingress_ssh" {\n'
        '  type = "ingress"\n'
        '  from_port = 22\n'
        '  to_port = 22\n'
        '  cidr_blocks = ["10.0.0.0/16"]\n'
        '}'
    )

    updated = find_and_replace_hcl_resource(
        original_hcl=original_hcl,
        resource_type="aws_security_group_rule",
        resource_name="ingress_ssh",
        replacement_block=replacement,
    )

    assert 'cidr_blocks = ["10.0.0.0/16"]' in updated
    assert 'cidr_blocks = ["0.0.0.0/0"]' not in updated
    # Preserves other resources
    assert 'resource "aws_s3_bucket" "b"' in updated


def test_create_unified_diff(tmp_path):
    orig_file = tmp_path / "main.tf"
    orig_file.write_text('cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
    proposed = 'cidr_blocks = ["10.0.0.0/16"]\n'

    diff = create_unified_diff(str(orig_file), proposed)
    assert "-cidr_blocks = [\"0.0.0.0/0\"]" in diff
    assert "+cidr_blocks = [\"10.0.0.0/16\"]" in diff


def test_remediate_patch_generation():
    client = GeminiClient(api_key=None)
    v = Violation(
        id="SEC-001",
        rule="open_security_groups",
        category="security",
        severity="high",
        resource="aws_security_group_rule.ingress_ssh",
        message="Allows 0.0.0.0/0 on port 22",
        resource_config={"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
    )

    patch_data = generate_patch_for_violation(v, client=client)
    assert "patch" in patch_data
    assert "10.0.0.0/16" in patch_data["patch"]
    assert v.patch is not None
