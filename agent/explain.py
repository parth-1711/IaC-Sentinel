"""Violation explanation generator using Gemini LLM."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from scanner.parse_violations import Violation
from agent.llm_client import GeminiClient

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "explain.txt"


def load_explain_prompt_template() -> str:
    """Reads the explanation prompt template from disk."""
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def explain_violation(
    violation: Violation,
    client: Optional[GeminiClient] = None,
    template: Optional[str] = None,
) -> str:
    """
    Renders the prompt for a specific violation and invokes the LLM client
    to obtain a plain-language risk explanation and suggested HCL fix.
    """
    if not client:
        client = GeminiClient()

    raw_template = template or load_explain_prompt_template()

    # Format resource config nicely as JSON string
    config_str = json.dumps(violation.resource_config, indent=2) if violation.resource_config else "{}"

    prompt = (
        raw_template
        .replace("{{rule_name}}", violation.rule)
        .replace("{{severity}}", violation.severity.upper())
        .replace("{{resource_address}}", violation.resource)
        .replace("{{resource_config_json}}", config_str)
    )

    explanation = client.generate_text(prompt)
    violation.explanation = explanation
    return explanation


def enrich_violations_with_explanations(
    violations: list[Violation],
    client: Optional[GeminiClient] = None,
) -> list[Violation]:
    """Iterates through all violations and enriches them in-place with plain-language explanations."""
    if not client:
        client = GeminiClient()

    template = load_explain_prompt_template()
    for v in violations:
        explain_violation(v, client=client, template=template)

    return violations
