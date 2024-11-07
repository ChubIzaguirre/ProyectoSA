#main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider configuration for management account
provider "aws" {
  region = "us-east-1"
  alias  = "management"
}

# AWS Organizations configuration
resource "aws_organizations_organization" "main" {
  provider = aws.management
  
  feature_set = "ALL"
  
  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY"
  ]
}

# Create Organizational Units
resource "aws_organizations_organizational_unit" "finance" {
  provider = aws.management
  name      = "Finance"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "hr" {
  provider = aws.management
  name      = "HR"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "it" {
  provider = aws.management
  name      = "IT"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# Security Hub configuration for management account
resource "aws_securityhub_account" "main" {
  provider = aws.management
  enable_default_standards = true
}

# GuardDuty configuration for management account
resource "aws_guardduty_detector" "main" {
  provider = aws.management
  enable = true
}

# Macie configuration for management account
resource "aws_macie2_account" "main" {
  provider = aws.management
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status = "ENABLED"
}

# S3 bucket for centralized logging
resource "aws_s3_bucket" "security_logs" {
  provider = aws.management
  bucket = "security-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "security_logs" {
  provider = aws.management
  bucket = aws_s3_bucket.security_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# KMS key for encryption
resource "aws_kms_key" "security" {
  provider = aws.management
  description = "KMS key for security services encryption"
  enable_key_rotation = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "kms:*"
        Resource = "*"
      }
    ]
  })
}