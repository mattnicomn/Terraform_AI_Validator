# =============================================================================
# AI Validator — Terraform remote-state BOOTSTRAP (account 102726256311)
# Creates the S3 state bucket used by ../infra/application. This layer uses
# LOCAL state itself (it cannot create the backend it uses) and is applied ONCE
# at a future authorized bootstrap gate.
#
# Terraform >= 1.10 supports S3-native state locking (use_lockfile), so a
# DynamoDB lock table is NOT required. (If a pre-1.10 constraint is later
# discovered, add a lock table then.)
# Phase 2 refactor — NOT YET APPLIED. No terraform init/plan/apply.
# =============================================================================

terraform {
  required_version = ">= 1.10.0" # S3-native locking (use_lockfile) — no DynamoDB needed
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80"
    }
  }
  # Intentionally LOCAL state for bootstrap (do not configure a remote backend here).
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  state_bucket = "ai-validator-tfstate-${data.aws_caller_identity.current.account_id}"
  tags = {
    Project   = "ai-validator"
    Purpose   = "terraform-remote-state"
    ManagedBy = "Terraform_AI_Validator/bootstrap"
  }
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.state_bucket
  tags   = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

variable "region" {
  type    = string
  default = "us-east-1"
}

output "state_bucket" {
  value = aws_s3_bucket.tfstate.id
}

output "backend_config_hint" {
  description = "Use these values with -backend-config at the application init gate."
  value = {
    bucket       = aws_s3_bucket.tfstate.id
    key          = "application/terraform.tfstate"
    region       = var.region
    use_lockfile = true
    encrypt      = true
  }
}
