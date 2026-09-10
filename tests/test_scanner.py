"""Unit tests for scanner, OPA execution, and violation normalization."""

from __future__ import annotations
import json
from pathlib import Path
import pytest
from scanner.parse_violations import normalize_violations, calculate_compliance_score
from scanner.run_opa import run_opa_eval, find_opa_binary

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


def test_compliance_score_calculation():
    # 0 violations -> 100
    assert calculate_compliance_score(high=0, medium=0, low=0) == 100
    # 1 high -> 100 - 25 = 75
    assert calculate_compliance_score(high=1, medium=0, low=0) == 75
    # 1 high, 2 med, 1 low -> 100 - (25 + 20 + 5) = 50
    assert calculate_compliance_score(high=1, medium=2, low=1) == 50
    # Many violations floor at 0
    assert calculate_compliance_score(high=10, medium=10, low=10) == 0


def test_opa_binary_found():
    binary = find_opa_binary()
    assert binary is not None, "OPA binary should be discoverable on system"


def test_scan_bad_plan_detects_expected_violations():
    bad_plan = FIXTURES_DIR / "bad_plan.json"
    raw_violations = run_opa_eval(
        plan_path=str(bad_plan),
        policies_dir=str(POLICIES_DIR),
    )

    with open(bad_plan, "r", encoding="utf-8") as f:
        plan_data = json.load(f)

    result = normalize_violations(raw_violations, plan_data=plan_data, plan_path=str(bad_plan))

    assert result.summary.total_violations > 0
    assert result.summary.high_count >= 2
    assert result.summary.passed is False
    assert result.summary.compliance_score < 100

    # Verify that rule names are present
    rule_names = {v.rule for v in result.violations}
    assert "open_security_groups" in rule_names
    assert "public_s3_buckets" in rule_names


def test_scan_good_plan_passes_cleanly():
    good_plan = FIXTURES_DIR / "good_plan.json"
    raw_violations = run_opa_eval(
        plan_path=str(good_plan),
        policies_dir=str(POLICIES_DIR),
    )

    with open(good_plan, "r", encoding="utf-8") as f:
        plan_data = json.load(f)

    result = normalize_violations(raw_violations, plan_data=plan_data, plan_path=str(good_plan))

    assert result.summary.total_violations == 0
    assert result.summary.high_count == 0
    assert result.summary.passed is True
    assert result.summary.compliance_score == 100
