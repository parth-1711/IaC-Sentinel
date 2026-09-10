"""SQLite and JSON persistence layer for IaC Sentinel scans and audit history."""

from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from scanner.parse_violations import ScanResult, Violation, ScanSummary


DEFAULT_DB_PATH = "iac_sentinel.db"
DEFAULT_JSON_PATH = "dashboard/public/violations_log.json"


def init_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Initializes the SQLite schema for audit logging."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            repo TEXT NOT NULL,
            pr_number INTEGER,
            commit_sha TEXT,
            total_violations INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            compliance_score INTEGER NOT NULL,
            status TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            violation_id TEXT NOT NULL,
            rule TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            resource TEXT NOT NULL,
            message TEXT NOT NULL,
            file TEXT,
            explanation TEXT,
            suggested_fix TEXT,
            patch TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
        """
    )
    conn.commit()
    return conn


def log_scan(
    scan_result: ScanResult,
    repo: str = "terraform-production-infra",
    pr_number: Optional[int] = None,
    commit_sha: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
    export_json_path: Optional[str] = DEFAULT_JSON_PATH,
) -> int:
    """Persists a scan result to SQLite and optionally updates the dashboard JSON log."""
    conn = init_db(db_path)
    cursor = conn.cursor()

    timestamp = datetime.now(timezone.utc).isoformat()
    status = "PASSED" if scan_result.summary.passed else "FAILED"

    cursor.execute(
        """
        INSERT INTO scans (
            timestamp, repo, pr_number, commit_sha,
            total_violations, high_count, medium_count, low_count,
            compliance_score, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            repo,
            pr_number,
            commit_sha or "HEAD",
            scan_result.summary.total_violations,
            scan_result.summary.high_count,
            scan_result.summary.medium_count,
            scan_result.summary.low_count,
            scan_result.summary.compliance_score,
            status,
        ),
    )
    scan_id = cursor.lastrowid

    for v in scan_result.violations:
        cursor.execute(
            """
            INSERT INTO violations (
                scan_id, violation_id, rule, category, severity,
                resource, message, file, explanation, suggested_fix, patch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                v.id,
                v.rule,
                v.category,
                v.severity,
                v.resource,
                v.message,
                v.file,
                v.explanation,
                v.suggested_fix,
                v.patch,
            ),
        )

    conn.commit()
    conn.close()

    if export_json_path:
        export_to_json(db_path=db_path, output_path=export_json_path)

    return scan_id


def get_all_scans(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves all scan summaries with their associated violations."""
    if not Path(db_path).exists():
        return []

    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    scans = [dict(row) for row in cursor.fetchall()]

    for s in scans:
        cursor.execute("SELECT * FROM violations WHERE scan_id = ?", (s["id"],))
        s["violations"] = [dict(v) for v in cursor.fetchall()]

    conn.close()
    return scans


def export_to_json(db_path: str = DEFAULT_DB_PATH, output_path: str = DEFAULT_JSON_PATH) -> None:
    """Exports SQLite audit data into a JSON file consumable by the dashboard."""
    scans = get_all_scans(db_path)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(
            {
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "total_scans": len(scans),
                "scans": scans,
            },
            f,
            indent=2,
        )


def seed_demo_history(db_path: str = DEFAULT_DB_PATH, export_json_path: Optional[str] = DEFAULT_JSON_PATH) -> None:
    """Seeds realistic historical scan data across several days for the dashboard."""
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return

    now = datetime.now(timezone.utc)
    demo_records = [
        {
            "days_ago": 6,
            "repo": "infrastructure-live",
            "pr": 42,
            "commit": "a1b2c3d",
            "score": 45,
            "high": 2, "med": 2, "low": 1,
            "status": "FAILED",
            "violations": [
                ("SEC-001", "open_security_groups", "security", "high", "aws_security_group_rule.ssh", "Allows 0.0.0.0/0 on port 22", "modules/vpc/main.tf"),
                ("SEC-002", "public_s3_buckets", "security", "high", "aws_s3_bucket.logs", "S3 bucket has public-read ACL", "modules/storage/s3.tf"),
                ("COST-001", "oversized_instances", "cost", "medium", "aws_instance.worker", "Oversized instance m5.4xlarge in dev", "modules/compute/workers.tf"),
                ("GOV-001", "required_tags", "governance", "medium", "aws_s3_bucket.logs", "Missing Owner tag", "modules/storage/s3.tf"),
                ("COST-002", "missing_auto_shutdown_tags", "cost", "low", "aws_instance.worker", "Missing AutoShutdown tag in dev", "modules/compute/workers.tf"),
            ]
        },
        {
            "days_ago": 4,
            "repo": "payment-service-infra",
            "pr": 108,
            "commit": "8f3e21a",
            "score": 75,
            "high": 1, "med": 0, "low": 0,
            "status": "FAILED",
            "violations": [
                ("SEC-001", "open_security_groups", "security", "high", "aws_security_group_rule.db_ingress", "Allows 0.0.0.0/0 on port 5432", "security.tf")
            ]
        },
        {
            "days_ago": 2,
            "repo": "infrastructure-live",
            "pr": 44,
            "commit": "e5d6c7b",
            "score": 90,
            "high": 0, "med": 1, "low": 0,
            "status": "PASSED",
            "violations": [
                ("GOV-001", "required_tags", "governance", "medium", "aws_ebs_volume.cache", "Missing Project tag", "volumes.tf")
            ]
        },
        {
            "days_ago": 0,
            "repo": "auth-service-infra",
            "pr": 215,
            "commit": "c4d5e6f",
            "score": 100,
            "high": 0, "med": 0, "low": 0,
            "status": "PASSED",
            "violations": []
        }
    ]

    for record in demo_records:
        ts = (now - timedelta(days=record["days_ago"])).isoformat()
        cursor.execute(
            """
            INSERT INTO scans (
                timestamp, repo, pr_number, commit_sha,
                total_violations, high_count, medium_count, low_count,
                compliance_score, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                record["repo"],
                record["pr"],
                record["commit"],
                len(record["violations"]),
                record["high"],
                record["med"],
                record["low"],
                record["score"],
                record["status"]
            )
        )
        scan_id = cursor.lastrowid
        for v in record["violations"]:
            cursor.execute(
                """
                INSERT INTO violations (
                    scan_id, violation_id, rule, category, severity, resource, message, file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, v[0], v[1], v[2], v[3], v[4], v[5], v[6])
            )

    conn.commit()
    conn.close()

    if export_json_path:
        export_to_json(db_path=db_path, output_path=export_json_path)
