"""MongoDB and JSON persistence layer for IaC Sentinel scans and audit history."""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from pymongo import MongoClient, DESCENDING, ReturnDocument
from pymongo.database import Database

from scanner.parse_violations import ScanResult, Violation, ScanSummary


DEFAULT_MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DEFAULT_DB_NAME = os.environ.get("MONGO_DB_NAME", "iac_sentinel")

# NOTE: this must NOT live under dashboard/public — the Next.js dashboard now
# reads scan history live from MongoDB via an authenticated API route that
# filters by the signed-in user's GitHub repo access. A static export sitting
# in a web-servable directory would leak every scan, unfiltered, to anyone
# with the URL. This JSON file is kept only as an optional offline artifact.
DEFAULT_JSON_PATH = "data/violations_log.json"


def _get_db(
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    client: Optional[MongoClient] = None,
) -> Database:
    """Resolves a Mongo database handle, using an injected client (e.g. mongomock) when given."""
    if client is None:
        client = MongoClient(uri)
    return client[db_name]


def init_db(
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    client: Optional[MongoClient] = None,
) -> Database:
    """Ensures indexes exist for audit logging and returns the database handle."""
    db = _get_db(uri, db_name, client)
    db.scans.create_index([("timestamp", DESCENDING)])
    db.scans.create_index([("id", DESCENDING)], unique=True)
    return db


def _next_scan_id(db: Database) -> int:
    """Atomically allocates the next sequential scan id."""
    doc = db.counters.find_one_and_update(
        {"_id": "scan_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return doc["seq"]


def log_scan(
    scan_result: ScanResult,
    repo: str = "terraform-production-infra",
    pr_number: Optional[int] = None,
    commit_sha: Optional[str] = None,
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    export_json_path: Optional[str] = DEFAULT_JSON_PATH,
    client: Optional[MongoClient] = None,
) -> int:
    """Persists a scan result to MongoDB and optionally updates the dashboard JSON log."""
    db = init_db(uri, db_name, client)

    timestamp = datetime.now(timezone.utc).isoformat()
    status = "PASSED" if scan_result.summary.passed else "FAILED"
    scan_id = _next_scan_id(db)

    violation_docs = [
        {
            "violation_id": v.id,
            "rule": v.rule,
            "category": v.category,
            "severity": v.severity,
            "resource": v.resource,
            "message": v.message,
            "file": v.file,
            "explanation": v.explanation,
            "suggested_fix": v.suggested_fix,
            "patch": v.patch,
        }
        for v in scan_result.violations
    ]

    db.scans.insert_one(
        {
            "id": scan_id,
            "timestamp": timestamp,
            "repo": repo,
            "pr_number": pr_number,
            "commit_sha": commit_sha or "HEAD",
            "total_violations": scan_result.summary.total_violations,
            "high_count": scan_result.summary.high_count,
            "medium_count": scan_result.summary.medium_count,
            "low_count": scan_result.summary.low_count,
            "compliance_score": scan_result.summary.compliance_score,
            "status": status,
            "violations": violation_docs,
        }
    )

    if export_json_path:
        export_to_json(uri=uri, db_name=db_name, output_path=export_json_path, client=client)

    return scan_id


def get_all_scans(
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    client: Optional[MongoClient] = None,
) -> List[Dict[str, Any]]:
    """Retrieves all scan summaries with their embedded violations, newest first."""
    db = init_db(uri, db_name, client)
    return list(db.scans.find({}, {"_id": 0}).sort("timestamp", DESCENDING))


def export_to_json(
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    output_path: str = DEFAULT_JSON_PATH,
    client: Optional[MongoClient] = None,
) -> None:
    """Exports MongoDB audit data into a JSON file consumable by the dashboard."""
    scans = get_all_scans(uri=uri, db_name=db_name, client=client)
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


def seed_demo_history(
    uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    export_json_path: Optional[str] = DEFAULT_JSON_PATH,
    client: Optional[MongoClient] = None,
) -> None:
    """Seeds realistic historical scan data across several days for the dashboard."""
    db = init_db(uri, db_name, client)

    if db.scans.count_documents({}) > 0:
        return

    now = datetime.now(timezone.utc)
    # NOTE: repo names must be real "owner/repo" full names (matching GitHub's
    # API) for the authenticated dashboard to show them — it filters scans by
    # the signed-in user's actual GitHub repo access. Replace these
    # placeholders with a repo you have access to before seeding if you want
    # to see demo data through the dashboard.
    demo_records = [
        {
            "days_ago": 6,
            "repo": "your-github-username/infrastructure-live",
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
            "repo": "your-github-username/payment-service-infra",
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
            "repo": "your-github-username/infrastructure-live",
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
            "repo": "your-github-username/auth-service-infra",
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
        scan_id = _next_scan_id(db)
        violation_docs = [
            {
                "violation_id": v[0],
                "rule": v[1],
                "category": v[2],
                "severity": v[3],
                "resource": v[4],
                "message": v[5],
                "file": v[6],
            }
            for v in record["violations"]
        ]
        db.scans.insert_one(
            {
                "id": scan_id,
                "timestamp": ts,
                "repo": record["repo"],
                "pr_number": record["pr"],
                "commit_sha": record["commit"],
                "total_violations": len(record["violations"]),
                "high_count": record["high"],
                "medium_count": record["med"],
                "low_count": record["low"],
                "compliance_score": record["score"],
                "status": record["status"],
                "violations": violation_docs,
            }
        )

    if export_json_path:
        export_to_json(uri=uri, db_name=db_name, output_path=export_json_path, client=client)
