terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  # normalize a map of per-bucket tags (adds a Name tag)
  bucket_tags = {
    for k, v in var.buckets :
    k => merge(var.tags, coalesce(v.tags, {}), { Name = v.name })
  }
}

# Create the buckets
resource "aws_s3_bucket" "this" {
  for_each = var.buckets

  bucket        = each.value.name
  force_destroy = try(each.value.force_destroy, false)

  # NOTE: Versioning optionally added below via separate resource
}

# Public Access Block (all locked down, as in your CFN)
resource "aws_s3_bucket_public_access_block" "this" {
  for_each = aws_s3_bucket.this

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ownership controls — your CFN used:
# - source/destination: BucketOwnerEnforced
# - results: BucketOwnerPreferred
resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    object_ownership = lookup(var.buckets[each.key], "ownership", "BucketOwnerEnforced")
  }
}

# Default SSE-S3 encryption (AES256), matching CFN
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Optional versioning
resource "aws_s3_bucket_versioning" "this" {
  for_each = {
    for k, v in aws_s3_bucket.this :
    k => v if try(var.buckets[k].versioning, false)
  }

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ------------------------------
# OPTIONAL bucket policies
#   - Allow principals to READ from the source bucket
#   - Allow principals to WRITE + TAG to destination/results buckets
# Supply the principal ARNs via variables; if none supplied, policies are skipped.
# ------------------------------

# Source read policy
data "aws_iam_policy_document" "source_read" {
  for_each = {
    for k, v in var.buckets :
    k => v
    if k == var.source_key && length(var.source_read_principals) > 0
  }

  statement {
    sid     = "AllowSourceReadFromPrincipals"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.buckets[var.source_key].name}/*"]

    principals {
      type        = "AWS"
      identifiers = var.source_read_principals
    }
  }
}

resource "aws_s3_bucket_policy" "source_read" {
  for_each = data.aws_iam_policy_document.source_read

  bucket = aws_s3_bucket.this[var.source_key].id
  policy = each.value.json
}

# Destination write/tag policy
data "aws_iam_policy_document" "dest_write" {
  for_each = {
    for k, v in var.buckets :
    k => v
    if k == var.destination_key && length(var.dest_write_principals) > 0
  }

  statement {
    sid     = "AllowDestWriteFromPrincipals"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["arn:aws:s3:::${var.buckets[var.destination_key].name}/*"]

    principals {
      type        = "AWS"
      identifiers = var.dest_write_principals
    }
  }
}

resource "aws_s3_bucket_policy" "dest_write" {
  for_each = data.aws_iam_policy_document.dest_write

  bucket = aws_s3_bucket.this[var.destination_key].id
  policy = each.value.json
}

# Results write/tag policy
data "aws_iam_policy_document" "results_write" {
  for_each = {
    for k, v in var.buckets :
    k => v
    if k == var.results_key && length(var.results_write_principals) > 0
  }

  statement {
    sid     = "AllowResultsWriteFromPrincipals"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["arn:aws:s3:::${var.buckets[var.results_key].name}/*"]

    principals {
      type        = "AWS"
      identifiers = var.results_write_principals
    }
  }
}

resource "aws_s3_bucket_policy" "results_write" {
  for_each = data.aws_iam_policy_document.results_write

  bucket = aws_s3_bucket.this[var.results_key].id
  policy = each.value.json
}
