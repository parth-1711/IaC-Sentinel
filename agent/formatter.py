"""Formatting utilities for PR comments, terminal outputs, and compliance reports."""

from __future__ import annotations
from typing import List, Optional
from scanner.parse_violations import ScanResult, Violation


def format_pr_comment(scan_result: ScanResult) -> str:
    """Renders a rich GitHub PR comment in Markdown format."""
    summary = scan_result.summary

    status_badge = "🟢 **PASSED**" if summary.passed else "🔴 **FAILED (Action Required)**"
    score_emoji = "🟢" if summary.compliance_score >= 85 else ("🟡" if summary.compliance_score >= 60 else "🔴")

    lines = [
        "## 🛡️ IaC Sentinel — Compliance Review",
        "",
        f"**Status:** {status_badge}  |  **Compliance Score:** {score_emoji} `{summary.compliance_score}/100`",
        "",
        "| Severity | Category | Rule | Resource | Message |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for v in scan_result.violations:
        sev_badge = {
            "high": "🔴 `HIGH`",
            "medium": "🟡 `MED`",
            "low": "🔵 `LOW`",
        }.get(v.severity.lower(), v.severity)

        cat_badge = v.category.capitalize()
        # Clean rule name
        rule_name = f"`{v.rule}`"
        res_name = f"`{v.resource}`"
        msg = v.message.replace("|", "\\|")
        lines.append(f"| {sev_badge} | {cat_badge} | {rule_name} | {res_name} | {msg} |")

    lines.extend([
        "",
        "---",
        "### 🤖 AI Risk Analysis & Proposed Remediation",
        "",
    ])

    for v in scan_result.violations:
        lines.append(f"<details><summary><b>[{v.severity.upper()}] {v.resource} ({v.rule})</b></summary>")
        lines.append("")

        if v.explanation:
            lines.append("**Risk & Context:**")
            lines.append(v.explanation)
            lines.append("")

        if v.patch:
            lines.append("**Suggested Compliant HCL Block:**")
            lines.append("```hcl")
            lines.append(v.patch.strip())
            lines.append("```")
            lines.append("")

        lines.append("</details>")
        lines.append("")

    lines.extend([
        "---",
        "*Report generated automatically by [IaC Sentinel](https://github.com/IaC-Sentinel). Safe agent architecture: Remediation proposals are suggested diffs only and will never overwrite code directly.*",
    ])

    return "\n".join(lines)


def format_terminal_summary(scan_result: ScanResult) -> str:
    """Formats a concise terminal summary for local CLI usage."""
    summary = scan_result.summary
    header = (
        f"\n=======================================================\n"
        f"             🛡️  IaC SENTINEL SCAN REPORT              \n"
        f"=======================================================\n"
        f" Status: {'PASSED' if summary.passed else 'FAILED'}\n"
        f" Compliance Score: {summary.compliance_score}/100\n"
        f" Violations: Total={summary.total_violations} (High={summary.high_count}, Med={summary.medium_count}, Low={summary.low_count})\n"
        f" Breakdown: Security={summary.security_count}, Cost={summary.cost_count}, Governance={summary.governance_count}\n"
        f"-------------------------------------------------------\n"
    )

    details = []
    for v in scan_result.violations:
        details.append(
            f" [{v.severity.upper()}] [{v.category.upper()}] {v.rule}\n"
            f"   Resource: {v.resource}\n"
            f"   Message:  {v.message}\n"
        )

    return header + "".join(details) + "=======================================================\n"
