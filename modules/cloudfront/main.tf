resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = var.oac_name
  description                       = ""
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Look up AWS Managed policies by name
data "aws_cloudfront_cache_policy" "this" {
  for_each = toset(var.cache_policy_names)
  name     = each.key
}

data "aws_cloudfront_origin_request_policy" "this" {
  for_each = toset(var.origin_request_policy_names)
  name     = each.key
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "index.html"
  default_root_object = "index.html"
  price_class         = "PriceClass_All"
  aliases             = var.aliases

  origin {
    domain_name              = var.s3_bucket_domain
    origin_id                = var.default_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
    s3_origin_config {}
  }

  default_cache_behavior {
    target_origin_id       = var.default_origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"]
    cached_methods         = ["GET","HEAD","OPTIONS"]
    compress               = true

    # Using managed policies
    cache_policy_id            = data.aws_cloudfront_cache_policy.this["Managed-CachingDisabled"].id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.this["Managed-AllViewerExceptHostHeader"].id

    dynamic "response_headers_policy_id" {
      for_each = var.response_headers_policy_id != "" ? [1] : []
      content  = var.response_headers_policy_id
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"
    ssl_support_method             = "vip"
  }

  tags = var.tags
}

# Optional S3 bucket policy to allow CloudFront distribution
resource "aws_s3_bucket_policy" "allow_cf" {
  count  = var.create_s3_policy ? 1 : 0
  bucket = replace(var.s3_bucket_arn, "arn:aws:s3:::", "")
  policy = jsonencode({
    Version = "2008-10-17"
    Id      = "PolicyForCloudFrontPrivateContent"
    Statement = [{
      Sid      = "AllowCloudFrontServicePrincipal"
      Effect   = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action   = "s3:GetObject"
      Resource = "${var.s3_bucket_arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = var.distribution_arn
        }
      }
    }]
  })
}

output "distribution_id"  { value = aws_cloudfront_distribution.this.id }
output "distribution_arn" { value = aws_cloudfront_distribution.this.arn }
output "domain_name"      { value = aws_cloudfront_distribution.this.domain_name }
