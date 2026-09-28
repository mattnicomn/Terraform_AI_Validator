# =============================================================================
# AI Validator — destination application provider + backend
# Account 102726256311. Account-agnostic: no profile/account hard-coded here.
# Backend is remote S3 (bootstrapped separately in ../../bootstrap). The
# application layer MUST NOT create the backend it uses.
# Phase 2 refactor — NOT YET APPLIED. Do not terraform init/plan/apply.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }

  # Remote state (S3 native locking, Terraform >= 1.10 uses use_lockfile).
  # Values are provided via -backend-config at a FUTURE authorized init gate.
  # Bucket/key/region intentionally left to backend-config to avoid embedding
  # account-specific values in source.
  backend "s3" {
    # bucket       = "ai-validator-tfstate-102726256311"   # via -backend-config
    # key          = "application/terraform.tfstate"        # via -backend-config
    # region       = "us-east-1"                            # via -backend-config
    # use_lockfile = true                                   # S3-native lock (TF >= 1.10)
    # encrypt      = true
  }
}

provider "aws" {
  region = var.region
  # No profile/account hard-coded. Credentials via SSO profile
  # (usmissionhero-ai-dev-sso) or CI OIDC role at deploy time.
  # default_tags uses provider-safe tags only (no account-id/data-source value)
  # to avoid a provider<->data-source dependency cycle.
  default_tags {
    tags = local.provider_tags
  }
}

# CloudFront + its ACM certificate must be in us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = local.provider_tags
  }
}
