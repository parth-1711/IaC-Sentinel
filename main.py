#!/usr/bin/env python3
"""IaC Sentinel — CLI Entrypoint for AI-augmented Terraform compliance checking."""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Ensure UTF-8 output encoding across Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass


from scanner.run_opa import run_opa_eval, find_opa_binary
from scanner.parse_violations import normalize_violations, ScanResult
from scanner.storage import log_scan, seed_demo_history, DEFAULT_MONGO_URI, DEFAULT_DB_NAME
from agent.explain import enrich_violations_with_explanations
from agent.remediate import remediate_all
from agent.formatter import format_pr_comment, format_terminal_summary
from agent.llm_client import GeminiClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iac-sentinel",
        description="IaC Sentinel: AI-augmented Terraform compliance agent.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # SCAN command
    scan_parser = subparsers.add_parser("scan", help="Scan a Terraform plan JSON against compliance policies")
    scan_parser.add_argument("--plan", required=True, help="Path to terraform plan JSON file (from `terraform show -json`)")
    scan_parser.add_argument("--policies", default="policies", help="Directory containing OPA Rego policies")
    scan_parser.add_argument("--explain", action="store_true", help="Generate AI plain-language risk explanations")
    scan_parser.add_argument("--remediate", action="store_true", help="Generate AI structured remediation patches & diffs")
    scan_parser.add_argument("--fail-on-high", action="store_true", default=True, help="Exit with non-zero code on high severity violations")
    scan_parser.add_argument("--no-fail-on-high", dest="fail_on_high", action="store_false", help="Do not exit with error on high violations (fail-open mode)")
    scan_parser.add_argument("--output-comment", help="Write GitHub PR comment Markdown to specified path")
    scan_parser.add_argument("--output-json", help="Write full normalized scan result JSON to specified path")
    scan_parser.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI, help="MongoDB connection URI for audit logging")
    scan_parser.add_argument("--log-db", default=DEFAULT_DB_NAME, help="MongoDB database name for audit logging (pass empty string to skip logging)")
    scan_parser.add_argument("--export-dashboard-json", default="data/violations_log.json", help="Optional path for an offline JSON export of scan history (NOT read by the dashboard — it reads MongoDB live via an authenticated API route; leave outside any web-servable directory)")
    scan_parser.add_argument("--repo", default="terraform-production-infra", help="Repository identifier for audit logs — use GitHub's 'owner/repo' format so the dashboard's GitHub-access filtering can match it")
    scan_parser.add_argument("--pr", type=int, help="Pull request number")
    scan_parser.add_argument("--commit", help="Commit SHA")
    scan_parser.add_argument("--target-tf", help="Optional path to base directory containing .tf source files for patch diffing")

    # TEST-POLICIES command
    test_parser = subparsers.add_parser("test-policies", help="Run OPA unit tests across all policies")
    test_parser.add_argument("--policies", default="policies", help="Policies directory")
    test_parser.add_argument("--tests", default="tests/policies", help="Tests directory")

    # SEED-DASHBOARD command
    seed_parser = subparsers.add_parser("seed-dashboard", help="Seed demo history into MongoDB and dashboard JSON")
    seed_parser.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI, help="MongoDB connection URI")
    seed_parser.add_argument("--db", default=DEFAULT_DB_NAME, help="MongoDB database name")
    seed_parser.add_argument("--json-out", default="data/violations_log.json", help="Optional offline JSON export path (not read by the dashboard)")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    if not plan_path.exists():
        print(f"Error: Plan file not found: {plan_path}", file=sys.stderr)
        return 2

    # Load raw plan JSON for resource context
    with open(plan_path, "r", encoding="utf-8") as f:
        try:
            plan_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error reading JSON from {plan_path}: {e}", file=sys.stderr)
            return 2

    print(f"[*] Scanning {plan_path} with OPA policies from '{args.policies}'...")

    raw_violations = run_opa_eval(
        plan_path=str(plan_path),
        policies_dir=args.policies,
    )

    scan_result = normalize_violations(
        raw_violations=raw_violations,
        plan_data=plan_data,
        plan_path=str(plan_path),
        fail_on_high=args.fail_on_high,
    )

    client = None
    if args.explain or args.remediate:
        client = GeminiClient()

    if args.explain:
        print("[*] Generating AI risk explanations with Gemini...")
        enrich_violations_with_explanations(scan_result.violations, client=client)

    if args.remediate:
        print("[*] Generating structured remediation patches and diffs...")
        base_tf_dir = args.target_tf or str(plan_path.parent)
        remediate_all(scan_result.violations, base_dir=base_tf_dir, client=client)

    # Output terminal summary
    print(format_terminal_summary(scan_result))

    # Output PR comment markdown if requested
    if args.output_comment:
        comment_md = format_pr_comment(scan_result)
        out_p = Path(args.output_comment)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(comment_md, encoding="utf-8")
        print(f"[+] Saved PR comment markdown to {out_p}")

    # Output JSON if requested
    if args.output_json:
        out_j = Path(args.output_json)
        out_j.parent.mkdir(parents=True, exist_ok=True)
        out_j.write_text(scan_result.to_json(), encoding="utf-8")
        print(f"[+] Saved scan JSON to {out_j}")

    # Log to MongoDB and export to dashboard JSON
    if args.log_db:
        scan_id = log_scan(
            scan_result=scan_result,
            repo=args.repo,
            pr_number=args.pr,
            commit_sha=args.commit,
            uri=args.mongo_uri,
            db_name=args.log_db,
            export_json_path=args.export_dashboard_json,
        )
        print(f"[+] Persisted scan #{scan_id} to MongoDB database '{args.log_db}'")

    if args.fail_on_high and not scan_result.summary.passed:
        print("[-] Scan failed: High-severity compliance violations detected.", file=sys.stderr)
        return 1

    return 0


def handle_test_policies(args: argparse.Namespace) -> int:
    import subprocess
    opa_bin = find_opa_binary() or "opa"
    cmd = [opa_bin, "test", args.policies, args.tests, "-v"]
    print(f"[*] Running OPA tests: {' '.join(cmd)}")
    res = subprocess.run(cmd)
    return res.returncode


def handle_seed_dashboard(args: argparse.Namespace) -> int:
    print(f"[*] Seeding demo compliance scan history into MongoDB database '{args.db}' and {args.json_out}...")
    seed_demo_history(uri=args.mongo_uri, db_name=args.db, export_json_path=args.json_out)
    print("[+] Successfully seeded demo data for dashboard!")
    return 0


# this feature is for making policies based upon the description recieved from user will implement this later
# def generate_policies(args: argparse.Namespace) -> int:
#     print(f"[*] Generating policies from {args.description}, {args.category} and {args.severity}...")
#     generate_custom_policies(policy_dir=args.policies, rules_dir=args.rules)
#     print("[+] Successfully generated custom policies!")
#     return 0

def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(handle_scan(args))
    elif args.command == "test-policies":
        sys.exit(handle_test_policies(args))
    elif args.command == "seed-dashboard":
        sys.exit(handle_seed_dashboard(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
