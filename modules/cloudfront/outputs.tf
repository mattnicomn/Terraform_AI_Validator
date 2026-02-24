output "distribution_id"  { value = aws_cloudfront_distribution.this.id }
output "distribution_arn" { value = aws_cloudfront_distribution.this.arn }
output "domain_name"      { value = aws_cloudfront_distribution.this.domain_name }

output "public_key_id" {
  value       = try(aws_cloudfront_public_key.this[0].id, null)
  description = "CloudFront public key ID for signed URLs"
}

output "key_group_id" {
  value       = try(aws_cloudfront_key_group.this[0].id, null)
  description = "CloudFront key group ID"
}
