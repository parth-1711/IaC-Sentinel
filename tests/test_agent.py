"""Unit tests for AI compliance agent explanation generation."""

from __future__ import annotations
from pathlib import Path
from scanner.parse_violations import Violation
from agent.explain import explain_violation, load_explain_prompt_template, enrich_violations_with_explanations
from agent.llm_client import GeminiClient
from agent.formatter import format_pr_comment, format_terminal_summary


def test_explain_prompt_template_loads():
    template = load_explain_prompt_template()
    assert "{{rule_name}}" in template
    assert "{{severity}}" in template
    assert "{{resource_address}}" in template
    assert "{{resource_config_json}}" in template
    assert "Why this matters" in template
    assert "Suggested fix" in template


def test_explain_violation_generates_two_sections():
    client = GeminiClient(api_key=None)  # Use deterministic fallback
    v = Violation(
        id="SEC-001",
        rule="open_security_groups",
        category="security",
        severity="high",
        resource="aws_security_group_rule.ingress_ssh",
        message="Allows 0.0.0.0/0 on port 22",
        resource_config={"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
    )

    explanation = explain_violation(v, client=client)
    assert v.explanation is not None
    assert "Why this matters" in explanation
    assert "Suggested fix" in explanation


def test_pr_comment_formatting():
    v = Violation(
        id="SEC-001",
        rule="open_security_groups",
        category="security",
        severity="high",
        resource="aws_security_group_rule.ingress_ssh",
        message="Allows 0.0.0.0/0 on port 22",
        explanation="Attackers can scan and brute force port 22.",
        patch='resource "aws_security_group_rule" "ingress_ssh" { ... }',
    )
    from scanner.parse_violations import ScanSummary, ScanResult
    summary = ScanSummary(total_violations=1, high_count=1, passed=False, compliance_score=75)
    scan_result = ScanResult(violations=[v], summary=summary)

    comment = format_pr_comment(scan_result)
    assert "IaC Sentinel — Compliance Review" in comment
    assert "open_security_groups" in comment
    assert "Why this matters" not in comment or "Attackers can scan" in comment
    assert "FAILED" in comment
