output "bucket_ids" {
  description = "Map of logical key => bucket id"
  value       = { for k, v in aws_s3_bucket.this : k => v.id }
}

output "bucket_arns" {
  description = "Map of logical key => bucket ARN"
  value       = { for k, v in aws_s3_bucket.this : k => v.arn }
}

output "names" {
  description = "Map of logical key => bucket name"
  value       = { for k, v in var.buckets : k => v.name }
}

# Add individual outputs for frontend bucket (used by CloudFront)
output "bucket_id" {
  description = "ID of the first bucket (for single-bucket usage)"
  value       = try(values(aws_s3_bucket.this)[0].id, null)
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the first bucket (for CloudFront)"
  value       = try(values(aws_s3_bucket.this)[0].bucket_regional_domain_name, null)
}
