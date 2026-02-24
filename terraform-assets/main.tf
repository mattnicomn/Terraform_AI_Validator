# US Mission Hero - Terraform Configuration
# This manages your S3 frontend assets and references existing CloudFront

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80"
    }
  }
}

provider "aws" {
  region = var.region
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Reference existing CloudFront distribution
data "aws_cloudfront_distribution" "existing" {
  id = var.cloudfront_distribution_id
}

# Locals
locals {
  common_tags = {
    Project     = var.project
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "Terraform"
  }
}

####################
# S3 Frontend Bucket
####################
resource "aws_s3_bucket" "frontend" {
  bucket        = var.bucket_name
  force_destroy = var.allow_destroy
  
  tags = merge(local.common_tags, {
    Name = "US Mission Hero Frontend"
  })
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

####################
# S3 Bucket Policy for CloudFront
####################
resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.frontend.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = data.aws_cloudfront_distribution.existing.arn
          }
        }
      }
    ]
  })
}

####################
# S3 Assets Upload
####################
resource "aws_s3_object" "index_html" {
  bucket        = aws_s3_bucket.frontend.id
  key           = "index.html"
  source        = "${path.module}/../modules/s3/index_Final.html"
  content_type  = "text/html"
  etag          = filemd5("${path.module}/../modules/s3/index_Final.html")
  cache_control = "public, max-age=3600"

  tags = merge(local.common_tags, {
    Asset = "HTML"
  })
}

resource "aws_s3_object" "logo" {
  bucket        = aws_s3_bucket.frontend.id
  key           = "assets/logo.png"
  source        = "${path.module}/../assets/US Mission Hero.png"
  content_type  = "image/png"
  etag          = filemd5("${path.module}/../assets/US Mission Hero.png")
  cache_control = "public, max-age=31536000, immutable"

  tags = merge(local.common_tags, {
    Asset = "Logo"
  })
}

resource "aws_s3_object" "logo_alt" {
  bucket        = aws_s3_bucket.frontend.id
  key           = "assets/US-Mission-Hero.png"
  source        = "${path.module}/../assets/US Mission Hero.png"
  content_type  = "image/png"
  etag          = filemd5("${path.module}/../assets/US Mission Hero.png")
  cache_control = "public, max-age=31536000, immutable"

  tags = merge(local.common_tags, {
    Asset = "Logo Alt"
  })
}

resource "aws_s3_object" "profile" {
  bucket        = aws_s3_bucket.frontend.id
  key           = "assets/profile.png"
  source        = "${path.module}/../assets/US Mission Hero.png"
  content_type  = "image/png"
  etag          = filemd5("${path.module}/../assets/US Mission Hero.png")
  cache_control = "public, max-age=31536000, immutable"

  tags = merge(local.common_tags, {
    Asset = "Profile"
  })
}

resource "aws_s3_object" "resume" {
  count = fileexists("${path.module}/../assets/Resume - Matthew Nico.pdf") ? 1 : 0

  bucket        = aws_s3_bucket.frontend.id
  key           = "assets/resume.pdf"
  source        = "${path.module}/../assets/Resume - Matthew Nico.pdf"
  content_type  = "application/pdf"
  etag          = filemd5("${path.module}/../assets/Resume - Matthew Nico.pdf")
  cache_control = "public, max-age=31536000, immutable"

  tags = merge(local.common_tags, {
    Asset = "Resume"
  })
}

####################
# Outputs
####################
output "bucket_name" {
  value       = aws_s3_bucket.frontend.id
  description = "Frontend S3 bucket name"
}

output "bucket_arn" {
  value       = aws_s3_bucket.frontend.arn
  description = "Frontend S3 bucket ARN"
}

output "cloudfront_url" {
  value       = "https://${data.aws_cloudfront_distribution.existing.domain_name}"
  description = "CloudFront distribution URL"
}

output "cloudfront_id" {
  value       = data.aws_cloudfront_distribution.existing.id
  description = "CloudFront distribution ID for cache invalidation"
}

output "assets_deployed" {
  value = {
    index_html = aws_s3_object.index_html.key
    logo       = aws_s3_object.logo.key
    logo_alt   = aws_s3_object.logo_alt.key
    profile    = aws_s3_object.profile.key
    resume     = length(aws_s3_object.resume) > 0 ? aws_s3_object.resume[0].key : "not deployed"
  }
  description = "List of deployed assets"
}

output "deployment_info" {
  value = {
    region      = data.aws_region.current.name
    account_id  = data.aws_caller_identity.current.account_id
    bucket      = aws_s3_bucket.frontend.id
    cloudfront  = data.aws_cloudfront_distribution.existing.domain_name
    managed_by  = "Terraform"
  }
  description = "Deployment information"
}
