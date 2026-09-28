output "cloudfront_domain" {
  description = "CloudFront distribution domain name."
  value       = aws_cloudfront_distribution.frontend.domain_name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}

output "bucket_id" {
  value = aws_s3_bucket.frontend.id
}

output "certificate_arn" {
  value = aws_acm_certificate_validation.frontend.certificate_arn
}
