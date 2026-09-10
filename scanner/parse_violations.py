"""Violation normalization and compliance evaluation module."""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import json


@dataclass
class Violation:
    id: str
    rule: str
    category: str  # "security" | "cost" | "governance"
    severity: str  # "high" | "medium" | "low"
    resource: str
    message: str
    resource_config: Dict[str, Any] = field(default_factory=dict)
    file: Optional[str] = None
    explanation: Optional[str] = None
    suggested_fix: Optional[str] = None
    patch: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    total_violations: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_count: int = 0
    cost_count: int = 0
    governance_count: int = 0
    compliance_score: int = 100
    passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    violations: List[Violation]
    summary: ScanSummary
    plan_path: Optional[str] = None
    scan_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "violations": [v.to_dict() for v in self.violations],
            "plan_path": self.plan_path,
            "scan_time": self.scan_time,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def calculate_compliance_score(high: int, medium: int, low: int) -> int:
    """Computes a 0-100 compliance health score."""
    penalty = (high * 25) + (medium * 10) + (low * 5)
    return max(0, 100 - penalty)


def normalize_violations(
    raw_violations: List[Dict[str, Any]],
    plan_data: Optional[Dict[str, Any]] = None,
    plan_path: Optional[str] = None,
    fail_on_high: bool = True,
) -> ScanResult:
    """
    Normalizes raw OPA violation dictionaries into standardized Violation objects
    and extracts matching resource configuration from the Terraform plan.
    """
    # Build a lookup map of resource_address -> resource_config from plan_data
    resource_configs: Dict[str, Dict[str, Any]] = {}
    if plan_data and "resource_changes" in plan_data:
        for rc in plan_data.get("resource_changes", []):
            addr = rc.get("address")
            if addr:
                change = rc.get("change", {})
                after = change.get("after") or {}
                resource_configs[addr] = {
                    "type": rc.get("type"),
                    "name": rc.get("name"),
                    "config": after,
                }

    normalized: List[Violation] = []
    category_counter: Dict[str, int] = {"security": 0, "cost": 0, "governance": 0}

    for idx, raw in enumerate(raw_violations, start=1):
        rule = raw.get("rule", "unknown_rule")
        category = raw.get("category", "security").lower()
        severity = raw.get("severity", "medium").lower()
        resource = raw.get("resource", "unknown_resource")
        message = raw.get("message", "Compliance rule violated.")

        category_counter[category] = category_counter.get(category, 0) + 1
        prefix = category[:3].upper()
        violation_id = f"{prefix}-{category_counter[category]:03d}"

        # Fetch config snippet if available
        rc_info = resource_configs.get(resource, {})
        rc_config = rc_info.get("config", raw.get("resource_config", {}))

        # Infer file location if available (or default to main.tf)
        file_path = raw.get("file") or "main.tf"

        normalized.append(
            Violation(
                id=violation_id,
                rule=rule,
                category=category,
                severity=severity,
                resource=resource,
                message=message,
                resource_config=rc_config,
                file=file_path,
            )
        )

    # Compute summary
    high = sum(1 for v in normalized if v.severity == "high")
    medium = sum(1 for v in normalized if v.severity == "medium")
    low = sum(1 for v in normalized if v.severity == "low")
    sec = sum(1 for v in normalized if v.category == "security")
    cost = sum(1 for v in normalized if v.category == "cost")
    gov = sum(1 for v in normalized if v.category == "governance")

    score = calculate_compliance_score(high, medium, low)
    passed = (high == 0) if fail_on_high else (len(normalized) == 0)

    summary = ScanSummary(
        total_violations=len(normalized),
        high_count=high,
        medium_count=medium,
        low_count=low,
        security_count=sec,
        cost_count=cost,
        governance_count=gov,
        compliance_score=score,
        passed=passed,
    )

    return ScanResult(violations=normalized, summary=summary, plan_path=plan_path)
