output "cloudfront_domain" {
  description = "CloudFront distribution domain name (null until Stage 2 / enable_frontend_delivery = true)."
  value       = try(aws_cloudfront_distribution.frontend[0].domain_name, null)
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution id (null until Stage 2)."
  value       = try(aws_cloudfront_distribution.frontend[0].id, null)
}

output "bucket_id" {
  value = aws_s3_bucket.frontend.id
}

output "certificate_arn" {
  description = "Validated ACM certificate ARN (null until Stage 2 validation completes)."
  value       = try(aws_acm_certificate_validation.frontend[0].certificate_arn, null)
}
