## 🛡️ IaC Sentinel — Compliance Review

**Status:** 🔴 **FAILED (Action Required)**  |  **Compliance Score:** 🔴 `0/100`

| Severity | Category | Rule | Resource | Message |
| :--- | :--- | :--- | :--- | :--- |
| 🔵 `LOW` | Cost | `missing_auto_shutdown_tags` | `aws_instance.ml_trainer_dev` | Non-production resource aws_instance.ml_trainer_dev in environment 'dev' is missing 'AutoShutdown' or 'Schedule' tag to curtail idle run spend |
| 🟡 `MED` | Cost | `oversized_instances` | `aws_instance.ml_trainer_dev` | EC2 instance aws_instance.ml_trainer_dev is provisioned with oversized instance type 'c5.4xlarge' exceeding cost budget limits |
| 🔵 `LOW` | Governance | `naming_conventions` | `aws_s3_bucket.customer_uploads` | S3 bucket name 'Customer_Uploads_Bucket' violates naming conventions (must use lowercase letters, numbers, and hyphens only) |
| 🔵 `LOW` | Governance | `naming_conventions` | `aws_security_group.app_sg` | Security group name 'App Security Group' violates naming conventions (must be lowercase kebab-case without spaces or uppercase letters) |
| 🟡 `MED` | Governance | `required_tags` | `aws_s3_bucket.customer_uploads` | Resource aws_s3_bucket.customer_uploads is missing mandatory governance tags: ["Owner", "Project"] |
| 🟡 `MED` | Governance | `required_tags` | `aws_security_group.app_sg` | Resource aws_security_group.app_sg is missing mandatory governance tags: ["Environment", "Owner", "Project"] |
| 🔴 `HIGH` | Security | `open_security_groups` | `aws_security_group.app_sg` | Security group aws_security_group.app_sg contains inline ingress allowing 0.0.0.0/0 on non-standard port 8080 |
| 🔴 `HIGH` | Security | `open_security_groups` | `aws_security_group_rule.ingress_ssh` | Security group rule aws_security_group_rule.ingress_ssh allows ingress from 0.0.0.0/0 on non-standard port 22 |
| 🔴 `HIGH` | Security | `public_s3_buckets` | `aws_s3_bucket.customer_uploads` | S3 bucket aws_s3_bucket.customer_uploads configured with dangerous public ACL 'public-read' |
| 🟡 `MED` | Security | `unencrypted_volumes` | `aws_ebs_volume.database_storage` | EBS volume aws_ebs_volume.database_storage is not encrypted at rest |

---
### 🤖 AI Risk Analysis & Proposed Remediation

<details><summary><b>[LOW] aws_instance.ml_trainer_dev (missing_auto_shutdown_tags)</b></summary>

**Risk & Context:**
Why this matters:
This resource configuration deviates from established organizational security and governance baselines, increasing exposure to compliance audit findings and unintended misconfigurations.

Suggested fix:
Update the resource configuration block to align with approved architecture guidelines and enforce least-privilege standards.

**Suggested Compliant HCL Block:**
```hcl
resource "aws_instance" "ml_trainer_dev" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"

  tags = {
    Environment  = "dev"
    Owner        = "ml-research"
    Project      = "recommendation"
    AutoShutdown = "true"
  }
}
```

</details>

<details><summary><b>[MEDIUM] aws_instance.ml_trainer_dev (oversized_instances)</b></summary>

**Risk & Context:**
Why this matters:
Provisioning large 4xlarge instances in development environments leads to steep, unnecessary cloud bills without proportional utilization. Runaway non-production compute is one of the highest drivers of cloud overspend.

Suggested fix:
Downscale the instance type to a cost-effective development tier such as t3.large or t3.xlarge with burstable capability.

resource "aws_instance" "ml_trainer_dev" {
  instance_type = "t3.large"
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_instance" "ml_trainer_dev" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"

  tags = {
    Environment  = "dev"
    Owner        = "ml-research"
    Project      = "recommendation"
    AutoShutdown = "true"
  }
}
```

</details>

<details><summary><b>[LOW] aws_s3_bucket.customer_uploads (naming_conventions)</b></summary>

**Risk & Context:**
Why this matters:
Granting public read ACL or omitting public access blocks allows unauthenticated internet users to browse, download, or leak sensitive customer data and application assets stored in the bucket. Attackers scrape public S3 buckets continuously to harvest credentials and intellectual property.

Suggested fix:
Change the bucket ACL to 'private' and attach an aws_s3_bucket_public_access_block resource enforcing all four public access restrictions.

resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"

  tags = {
    Environment = "dev"
    Owner       = "platform-team"
    Project     = "sentinel"
  }
}
```

</details>

<details><summary><b>[LOW] aws_security_group.app_sg (naming_conventions)</b></summary>

**Risk & Context:**
Why this matters:
This resource configuration deviates from established organizational security and governance baselines, increasing exposure to compliance audit findings and unintended misconfigurations.

Suggested fix:
Update the resource configuration block to align with approved architecture guidelines and enforce least-privilege standards.

**Suggested Compliant HCL Block:**
```hcl
# Compliant resource block
```

</details>

<details><summary><b>[MEDIUM] aws_s3_bucket.customer_uploads (required_tags)</b></summary>

**Risk & Context:**
Why this matters:
Granting public read ACL or omitting public access blocks allows unauthenticated internet users to browse, download, or leak sensitive customer data and application assets stored in the bucket. Attackers scrape public S3 buckets continuously to harvest credentials and intellectual property.

Suggested fix:
Change the bucket ACL to 'private' and attach an aws_s3_bucket_public_access_block resource enforcing all four public access restrictions.

resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"

  tags = {
    Environment = "dev"
    Owner       = "platform-team"
    Project     = "sentinel"
  }
}
```

</details>

<details><summary><b>[MEDIUM] aws_security_group.app_sg (required_tags)</b></summary>

**Risk & Context:**
Why this matters:
Untagged cloud resources create operational blindspots where cloud spend cannot be attributed to specific teams, and unowned infrastructure remains orphaned and unpatched.

Suggested fix:
Attach the mandatory organizational tags 'Environment', 'Owner', and 'Project' to the resource block.

tags = {
  Environment = "production"
  Owner       = "platform-team"
  Project     = "sentinel"
}

**Suggested Compliant HCL Block:**
```hcl
# Compliant resource block
```

</details>

<details><summary><b>[HIGH] aws_security_group.app_sg (open_security_groups)</b></summary>

**Risk & Context:**
Why this matters:
Opening port 22 or non-standard management ports directly to 0.0.0.0/0 exposes the host to constant automated brute-force attacks and zero-day SSH vulnerabilities across the public internet. Any attacker can reach the authentication service and attempt unauthorized remote code execution.

Suggested fix:
Restrict ingress CIDR blocks to an internal VPC bastion subnet (e.g., 10.0.0.0/16) or an authorized corporate VPN gateway, and utilize AWS Systems Manager (SSM) Session Manager instead of public SSH.

resource "aws_security_group_rule" "ingress_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_security_group_rule" "ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.app_sg.id
  description       = "Allow SSH from private VPC"
}
```

</details>

<details><summary><b>[HIGH] aws_security_group_rule.ingress_ssh (open_security_groups)</b></summary>

**Risk & Context:**
Why this matters:
Opening port 22 or non-standard management ports directly to 0.0.0.0/0 exposes the host to constant automated brute-force attacks and zero-day SSH vulnerabilities across the public internet. Any attacker can reach the authentication service and attempt unauthorized remote code execution.

Suggested fix:
Restrict ingress CIDR blocks to an internal VPC bastion subnet (e.g., 10.0.0.0/16) or an authorized corporate VPN gateway, and utilize AWS Systems Manager (SSM) Session Manager instead of public SSH.

resource "aws_security_group_rule" "ingress_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_security_group_rule" "ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.app_sg.id
  description       = "Allow SSH from private VPC"
}
```

</details>

<details><summary><b>[HIGH] aws_s3_bucket.customer_uploads (public_s3_buckets)</b></summary>

**Risk & Context:**
Why this matters:
Granting public read ACL or omitting public access blocks allows unauthenticated internet users to browse, download, or leak sensitive customer data and application assets stored in the bucket. Attackers scrape public S3 buckets continuously to harvest credentials and intellectual property.

Suggested fix:
Change the bucket ACL to 'private' and attach an aws_s3_bucket_public_access_block resource enforcing all four public access restrictions.

resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-bucket"
  acl    = "private"

  tags = {
    Environment = "dev"
    Owner       = "platform-team"
    Project     = "sentinel"
  }
}
```

</details>

<details><summary><b>[MEDIUM] aws_ebs_volume.database_storage (unencrypted_volumes)</b></summary>

**Risk & Context:**
Why this matters:
Unencrypted EBS volumes store raw database data and temporary files in plaintext on physical media. If snapshots are shared or the underlying hardware is decommissioned, unauthorized parties can access confidential records.

Suggested fix:
Set encrypted = true on the EBS volume and specify a Customer Managed KMS Key (CMK) for centralized key rotation.

resource "aws_ebs_volume" "database_storage" {
  size      = 250
  encrypted = true
}

**Suggested Compliant HCL Block:**
```hcl
resource "aws_ebs_volume" "database_storage" {
  availability_zone = "us-east-1a"
  size              = 250
  encrypted         = true

  tags = {
    Environment = "production"
    Owner       = "data-platform"
    Project     = "finance-db"
  }
}
```

</details>

---
*Report generated automatically by [IaC Sentinel](https://github.com/IaC-Sentinel). Safe agent architecture: Remediation proposals are suggested diffs only and will never overwrite code directly.*