"""OPA execution and evaluation runner."""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger("iac_sentinel.scanner")


def find_opa_binary() -> Optional[str]:
    """Locates the OPA executable across standard system and local paths."""
    # 1. Explicit environment variable
    if env_path := os.environ.get("OPA_PATH"):
        if os.path.exists(env_path):
            return env_path

    # 2. System PATH
    if path_bin := shutil.which("opa"):
        return path_bin

    # 3. Local project bin directory
    local_bin = Path(__file__).resolve().parent.parent / "bin" / ("opa.exe" if os.name == "nt" else "opa")
    if local_bin.exists():
        return str(local_bin)

    # 4. Common Windows winget / appdata paths
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            possible_winget = Path(local_app_data) / "Microsoft" / "WinGet" / "Links" / "opa.exe"
            if possible_winget.exists():
                return str(possible_winget)

    return None


def run_opa_eval(
    plan_path: str,
    policies_dir: Optional[str] = None,
    opa_bin: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Runs `opa eval` with the Terraform plan JSON as input and policies as data.
    Returns a list of raw violation dictionaries.
    """
    binary = opa_bin or find_opa_binary()
    if not binary:
        raise FileNotFoundError(
            "OPA binary not found. Please install OPA or set OPA_PATH to the executable."
        )

    if not policies_dir:
        policies_dir = str(Path(__file__).resolve().parent.parent / "policies")

    cmd = [
        binary,
        "eval",
        "--data", policies_dir,
        "--input", plan_path,
        "--format", "json",
        "data.iac_sentinel",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception as e:
        logger.error(f"Failed to execute OPA command: {e}")
        raise

    if proc.returncode != 0:
        logger.error(f"OPA eval error (exit code {proc.returncode}): {proc.stderr}")
        raise RuntimeError(f"OPA eval failed: {proc.stderr.strip()}")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse OPA JSON output: {proc.stdout}")
        raise RuntimeError(f"Invalid JSON from OPA: {e}")

    violations: List[Dict[str, Any]] = []
    # OPA eval result format: {"result": [{"expressions": [{"value": {"security": {...}, "cost": {...}, ...}}]}]}
    results = data.get("result", [])
    if results and "expressions" in results[0]:
        val = results[0]["expressions"][0].get("value", {})
        violations = _extract_violations_from_tree(val)

    return violations


def _extract_violations_from_tree(node: Any) -> List[Dict[str, Any]]:
    """Recursively traverses OPA package evaluation tree to gather all 'deny' messages."""
    violations: List[Dict[str, Any]] = []

    if isinstance(node, dict):
        if "deny" in node:
            deny_val = node["deny"]
            if isinstance(deny_val, list):
                violations.extend(deny_val)
            elif isinstance(deny_val, set):
                violations.extend(list(deny_val))
            elif isinstance(deny_val, dict):
                # OPA sometimes represents sets as dicts with boolean true values
                for k, v in deny_val.items():
                    if isinstance(k, dict):
                        violations.append(k)
                    elif isinstance(v, dict):
                        violations.append(v)
        for k, v in node.items():
            if k != "deny" and isinstance(v, (dict, list)):
                violations.extend(_extract_violations_from_tree(v))
    elif isinstance(node, list):
        for item in node:
            violations.extend(_extract_violations_from_tree(item))

    return violations
