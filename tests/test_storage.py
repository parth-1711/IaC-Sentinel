"""Unit tests for MongoDB audit logger and JSON export."""

from __future__ import annotations
from pathlib import Path
import mongomock
from scanner.parse_violations import Violation, ScanSummary, ScanResult
from scanner.storage import log_scan, get_all_scans, seed_demo_history


def test_mongo_logging_and_export(tmp_path):
    client = mongomock.MongoClient()
    json_path = str(tmp_path / "test_export.json")

    v = Violation(
        id="SEC-001",
        rule="open_security_groups",
        category="security",
        severity="high",
        resource="aws_security_group_rule.ingress_ssh",
        message="Open SSH",
        file="main.tf",
        explanation="Risk details",
        suggested_fix="Restrict CIDR",
        patch='resource "aws_security_group_rule" "ingress_ssh" { ... }',
    )
    summary = ScanSummary(total_violations=1, high_count=1, passed=False, compliance_score=75)
    result = ScanResult(violations=[v], summary=summary)

    scan_id = log_scan(
        scan_result=result,
        repo="my-org/my-infra",
        pr_number=10,
        commit_sha="abcdef1",
        db_name="test_sentinel",
        export_json_path=json_path,
        client=client,
    )

    assert scan_id == 1

    scans = get_all_scans(db_name="test_sentinel", client=client)
    assert len(scans) == 1
    assert scans[0]["repo"] == "my-org/my-infra"
    assert scans[0]["pr_number"] == 10
    assert len(scans[0]["violations"]) == 1
    assert scans[0]["violations"][0]["rule"] == "open_security_groups"

    # Verify JSON export
    assert Path(json_path).exists()
    import json
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_scans"] == 1
    assert data["scans"][0]["repo"] == "my-org/my-infra"


def test_seed_demo_history(tmp_path):
    client = mongomock.MongoClient()
    json_path = str(tmp_path / "demo.json")

    seed_demo_history(db_name="demo_sentinel", export_json_path=json_path, client=client)

    scans = get_all_scans(db_name="demo_sentinel", client=client)
    assert len(scans) == 4
    assert Path(json_path).exists()
