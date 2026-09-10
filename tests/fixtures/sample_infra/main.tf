# Infrastructure definition for app services
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VIOLATION: Ingress SSH open to the entire internet (0.0.0.0/0)
resource "aws_security_group_rule" "ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app_sg.id
  description       = "Allow SSH from anywhere"
}

# VIOLATION: S3 bucket with public-read ACL and bad naming convention
resource "aws_s3_bucket" "customer_uploads" {
  bucket = "Customer_Uploads_Bucket"
  acl    = "public-read"

  tags = {
    Environment = "dev"
  }
}

# VIOLATION: Unencrypted EBS volume
resource "aws_ebs_volume" "database_storage" {
  availability_zone = "us-east-1a"
  size              = 250
  encrypted         = false

  tags = {
    Environment = "production"
    Owner       = "data-platform"
    Project     = "finance-db"
  }
}

# VIOLATION: Oversized instance type for dev without auto shutdown
resource "aws_instance" "ml_trainer_dev" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "c5.4xlarge"

  tags = {
    Environment = "dev"
    Owner       = "ml-research"
    Project     = "recommendation"
  }
}

# VIOLATION: Invalid SG name with spaces and inline open ingress
resource "aws_security_group" "app_sg" {
  name        = "App Security Group"
  description = "App cluster security group"

  ingress {
    description = "Custom management port"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {}
}
