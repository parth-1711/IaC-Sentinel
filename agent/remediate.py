"""Remediation patch generator and proposal manager."""

from __future__ import annotations
import difflib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from scanner.parse_violations import Violation
from agent.llm_client import GeminiClient

logger = logging.getLogger("iac_sentinel.agent.remediate")
PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "remediate.txt"


def load_remediate_prompt_template() -> str:
    """Reads the remediation prompt template from disk."""
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def generate_patch_for_violation(
    violation: Violation,
    client: Optional[GeminiClient] = None,
    template: Optional[str] = None,
    file_context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Asks Gemini for a structured JSON remediation patch for a violation.
    """
    if not client:
        client = GeminiClient()

    raw_template = template or load_remediate_prompt_template()
    config_str = json.dumps(violation.resource_config, indent=2) if violation.resource_config else "{}"
    file_path = violation.file or "main.tf"

    prompt = (
        raw_template
        .replace("{{rule_name}}", violation.rule)
        .replace("{{severity}}", violation.severity.upper())
        .replace("{{resource_address}}", violation.resource)
        .replace("{{file_path}}", file_path)
        .replace("{{resource_config_json}}", config_str)
        .replace("{{file_context}}", f"File excerpt:\n{file_context}" if file_context else "")
    )

    patch_data = client.generate_structured_json(prompt)
    violation.patch = patch_data.get("patch", "")
    violation.suggested_fix = patch_data.get("explanation", "")
    return patch_data


def find_and_replace_hcl_resource(
    original_hcl: str,
    resource_type: str,
    resource_name: str,
    replacement_block: str,
) -> str:
    """
    Locates an HCL resource block `resource "<type>" "<name>" { ... }` in original_hcl
    and replaces it with the corrected replacement_block.
    """
    # Regex to find resource block start
    pattern = re.compile(
        rf'(resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{)',
        re.MULTILINE,
    )
    match = pattern.search(original_hcl)
    if not match:
        # Fallback: append or return unchanged
        return original_hcl

    start_idx = match.start()
    # Find matching closing brace
    depth = 0
    in_string = False
    escape = False
    end_idx = -1

    for i in range(match.end() - 1, len(original_hcl)):
        char = original_hcl[i]
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if not in_string:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_idx = i + 1
                    break

    if end_idx != -1:
        return original_hcl[:start_idx] + replacement_block.strip() + original_hcl[end_idx:]
    return original_hcl


def create_unified_diff(
    original_path: str,
    proposed_content: str,
) -> str:
    """Computes a unified diff between an existing file and proposed content."""
    orig_p = Path(original_path)
    if orig_p.exists():
        original_content = orig_p.read_text(encoding="utf-8")
    else:
        original_content = ""

    orig_lines = original_content.splitlines(keepends=True)
    prop_lines = proposed_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        orig_lines,
        prop_lines,
        fromfile=f"a/{orig_p.name}",
        tofile=f"b/{orig_p.name}",
    )
    return "".join(diff)


def remediate_all(
    violations: List[Violation],
    base_dir: Optional[str] = None,
    client: Optional[GeminiClient] = None,
) -> Dict[str, Any]:
    """
    Generates patches for all violations, calculates unified diffs,
    and returns a structured remediation summary.
    """
    if not client:
        client = GeminiClient()

    template = load_remediate_prompt_template()
    base_path = Path(base_dir) if base_dir else Path.cwd()

    remediations: List[Dict[str, Any]] = []
    file_diffs: Dict[str, str] = {}

    for v in violations:
        # Target file resolution
        rel_file = v.file or "main.tf"
        target_file = base_path / rel_file
        file_content = target_file.read_text(encoding="utf-8") if target_file.exists() else None

        patch_info = generate_patch_for_violation(
            violation=v,
            client=client,
            template=template,
            file_context=file_content[:500] if file_content else None,
        )

        patch_hcl = patch_info.get("patch", "")
        if patch_hcl and file_content:
            # Parse resource type and name from resource address (e.g. "aws_security_group_rule.ingress_ssh")
            parts = v.resource.split(".")
            if len(parts) >= 2:
                r_type, r_name = parts[0], parts[1]
                updated_hcl = find_and_replace_hcl_resource(
                    original_hcl=file_content,
                    resource_type=r_type,
                    resource_name=r_name,
                    replacement_block=patch_hcl,
                )
                diff = create_unified_diff(str(target_file), updated_hcl)
                file_diffs[rel_file] = diff
                patch_info["diff"] = diff

        remediations.append({
            "violation_id": v.id,
            "resource": v.resource,
            "rule": v.rule,
            "patch_info": patch_info,
        })

    return {
        "remediations": remediations,
        "file_diffs": file_diffs,
    }
