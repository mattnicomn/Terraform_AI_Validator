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
