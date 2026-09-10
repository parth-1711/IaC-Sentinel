# IaC Sentinel 🛡️
> **AI-Augmented Terraform Compliance Agent with Custom OPA Policies & Automated PR Remediation**

[![OPA Tests](https://img.shields.io/badge/OPA%20Tests-27%2F27%20Passing-emerald)](policies/)
[![Python Tests](https://img.shields.io/badge/Python%20Tests-12%2F12%20Passing-blue)](tests/)
[![Engine](https://img.shields.io/badge/OPA-v1.20%20(Rego%20v1)-purple)](policies/)
[![AI](https://img.shields.io/badge/AI-Google%20Gemini-orange)](agent/)
[![License](https://img.shields.io/badge/License-MIT-slate)](LICENSE)

IaC Sentinel evaluates Terraform execution plans against custom Open Policy Agent (OPA) compliance policies covering **Security**, **Cost**, and **Governance**. 

For every flagged violation, an LLM compliance agent generates:
1. A **plain-language risk explanation** explaining the concrete attacker threat or cost impact to developers.
2. A **structured HCL patch & proposed diff** that can be reviewed, merged, or automatically proposed as a secondary PR without ever touching production branches unreviewed.
3. A **compliance audit trail** logged to SQLite and visualizable via an interactive web dashboard.

---

## 💡 Why I Built This

Most infrastructure-as-code security tooling outputs cryptic linter codes or massive static analysis dumps that developers ignore or bypass. Meanwhile, fully autonomous AI agents that commit directly to infrastructure branches are dangerous and unacceptable in production environments.

**IaC Sentinel was built around two core philosophies:**
1. **Explain, don't just alert**: Developers fix misconfigurations faster when they understand *why* a policy matters (e.g. what an attacker can actually do with an open port) paired with an immediate, minimal Terraform HCL fix.
2. **Safe Agent Design (Propose, don't act)**: The agent operates exclusively through proposed diffs and secondary remediation PRs. Merges to main infrastructure branches always remain strictly in the hands of human engineers.

---

## 🏛️ Architecture & Data Flow

```
Pull Request Opens (*.tf modified)
         │
         ▼
`terraform plan` (exported as JSON via `terraform show -json`)
         │
         ▼
OPA Policy Engine (`policies/{security,cost,governance}/*.rego`)
         │
         ▼
Scanner & Normalizer (`scanner/run_opa.py`, `scanner/parse_violations.py`)
         │
         ▼
LLM Compliance Agent: Gemini (`agent/explain.py`, `agent/remediate.py`)
 ├── Explain: Plain-language risk explanation ("Why this matters" & "Suggested fix")
 └── Remediate: Structured JSON patch proposal & git diff
         │
    ┌────┴───────────────────────────┐
    ▼                                ▼
GitHub Action PR Comment      SQLite / JSON Audit Log (`iac_sentinel.db`)
(+ Optional Remediation PR)          │
                                     ▼
                              Compliance Dashboard (`dashboard/`)
```

---

## 📜 Policy Catalog

IaC Sentinel ships with 7 hand-written, production-ready Rego v1 policies accompanied by 27 unit tests (`opa test`):

| Pillar | Policy Rule | File | Severity | What it Enforces |
| :--- | :--- | :--- | :--- | :--- |
| 🔒 **Security** | `open_security_groups` | [`policies/security/open_security_groups.rego`](policies/security/open_security_groups.rego) | `HIGH` | Blocks ingress from `0.0.0.0/0` on sensitive ports (SSH, RDP, DB ports); allows only 80/443. |
| 🔒 **Security** | `public_s3_buckets` | [`policies/security/public_s3_buckets.rego`](policies/security/public_s3_buckets.rego) | `HIGH` | Blocks `public-read`/`public-read-write` ACLs and requires strict public access blocks. |
| 🔒 **Security** | `unencrypted_volumes` | [`policies/security/unencrypted_volumes.rego`](policies/security/unencrypted_volumes.rego) | `MEDIUM` | Enforces encryption at rest (`encrypted = true`) on all EBS volumes and EC2 root block devices. |
| 💰 **Cost** | `oversized_instances` | [`policies/cost/oversized_instances.rego`](policies/cost/oversized_instances.rego) | `MEDIUM` | Flags oversized EC2 instances (`*.2xlarge`, `*.4xlarge`, metal tiers) to control cloud spend. |
| 💰 **Cost** | `missing_auto_shutdown_tags` | [`policies/cost/missing_auto_shutdown_tags.rego`](policies/cost/missing_auto_shutdown_tags.rego) | `LOW` | Enforces `AutoShutdown` or `Schedule` tags on dev/staging instances to prevent idle run costs. |
| 🏷️ **Governance** | `required_tags` | [`policies/governance/required_tags.rego`](policies/governance/required_tags.rego) | `MEDIUM` | Enforces mandatory organizational tags: `Environment`, `Owner`, and `Project`. |
| 🏷️ **Governance** | `naming_conventions` | [`policies/governance/naming_conventions.rego`](policies/governance/naming_conventions.rego) | `LOW` | Enforces lowercase kebab-case naming standards on S3 buckets and security groups. |

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Open Policy Agent (`opa`) CLI ([Installation Guide](https://www.openpolicyagent.org/docs/latest/#1-download-opa))
- (Optional) `GEMINI_API_KEY` for live AI generation (a deterministic fallback is built-in for offline testing)

### 2. Setup Virtual Environment

```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Policy Tests & Unit Tests

```bash
# Run all 27 Rego policy unit tests
opa test policies/ tests/policies/ -v

# Run Python unit tests
pytest tests/ -v
```

### 4. Scan a Terraform Plan

```bash
# Scan non-compliant fixture and generate AI explanations + patches + PR comment
python main.py scan \
  --plan tests/fixtures/bad_plan.json \
  --explain \
  --remediate \
  --output-comment pr_comment.md \
  --output-json scan_result.json

# Scan compliant fixture (exits with code 0, 100/100 score)
python main.py scan --plan tests/fixtures/good_plan.json
```

---

## 🤖 GitHub Action CI Integration

Add `.github/workflows/iac-sentinel.yml` to your repository:

```yaml
name: "IaC Sentinel Compliance Check"

on:
  pull_request:
    paths:
      - "**/*.tf"

permissions:
  contents: read
  pull-requests: write

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform init -backend=false
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json

      - uses: ./github-action
        with:
          plan_file: "tfplan.json"
          policies_dir: "policies"
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          fail_on_high: "true"
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Fail-Open vs Fail-Closed Strategy
- **Fail-Closed (Default)**: Pull requests containing high-severity violations exit with code `1`, blocking merges until remediated.
- **Fail-Open (Override)**: Engineers can attach the PR label `skip-iac-sentinel` or `compliance-approved` to temporarily bypass blockers for urgent rollouts while preserving the audit comment.

---

## 📊 Compliance Dashboard

IaC Sentinel includes a modern telemetry portal in `dashboard/` reading from SQLite and JSON audit histories.

```bash
cd dashboard
npm install
npm run dev
```

Visit `http://localhost:3000` to view:
- **Compliance Health Scorecard**: Overall score (0-100), high blockers, and scan trends.
- **Historical Telemetry Graph**: Visual timeline of compliance improvements across PRs.
- **Pillar Distribution**: Breakdown across Security, Cost, and Governance.
- **Violation Inspector Modal**: Searchable findings with AI threat narrative and one-click copyable HCL patches.

---

## 📁 Repository Structure

```
iac-sentinel/
├── policies/                         # Custom OPA Rego v1 compliance rules
│   ├── security/                     # Open SGs, public S3, unencrypted EBS
│   ├── cost/                         # Oversized instances, auto-shutdown tags
│   └── governance/                   # Required tags, naming standards
├── scanner/                          # Evaluation and normalization engine
│   ├── run_opa.py                    # Evaluates plan JSON against OPA data tree
│   ├── parse_violations.py           # Normalizes findings into unified schema
│   └── storage.py                    # SQLite persistence & JSON export
├── agent/                            # AI Compliance Agent
│   ├── explain.py                    # LLM risk explanation generator
│   ├── remediate.py                  # Structured HCL patch generator & diffing
│   ├── llm_client.py                 # Gemini wrapper with fallback mode
│   ├── formatter.py                  # Markdown PR comments & CLI summary
│   └── prompts/                      # Strict system prompts (explain & remediate)
├── github-action/                    # Reusable GitHub Action
│   └── action.yml                    # CI composite entrypoint
├── dashboard/                        # Modern Compliance Web Portal
│   ├── src/                          # React + Vite dashboard components
│   └── public/violations_log.json    # Exported audit telemetry
├── tests/                            # Test suites & fixtures
│   ├── policies/                     # 27 Rego unit test cases (*_test.rego)
│   ├── fixtures/                     # Compliant and violating plan JSONs
│   ├── test_scanner.py               # Scanner unit tests
│   ├── test_agent.py                 # Agent explanation tests
│   ├── test_remediate.py             # Patch diff tests
│   └── test_storage.py               # SQLite logging tests
├── main.py                           # Unified CLI executable
├── requirements.txt                  # Python dependencies
└── README.md
```

---

## 🛡️ License

MIT License. Crafted for resilient, auditable cloud infrastructure.
