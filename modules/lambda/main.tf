resource "aws_cloudwatch_log_group" "lg" {
  name              = var.log_group_name
  retention_in_days = 30
  kms_key_id        = var.log_group_kms_key_id
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = var.role_arn
  timeout       = var.timeout
  memory_size   = var.memory_size
  architectures = var.architectures
  tags          = var.tags

  package_type = var.package_type

  # Image-based Lambda
  image_uri = var.package_type == "Image" && var.image_uri != null ? var.image_uri : null

  # Zip-based Lambda from S3
  s3_bucket         = var.package_type == "Zip" && var.code_s3_bucket != null ? var.code_s3_bucket : null
  s3_key            = var.package_type == "Zip" && var.code_s3_key != null ? var.code_s3_key : null
  s3_object_version = var.package_type == "Zip" && var.code_s3_version != null ? var.code_s3_version : null

  # Required for Zip packages
  handler = var.package_type == "Zip" ? var.handler : null
  runtime = var.package_type == "Zip" ? var.runtime : null
  
  # Lifecycle to prevent recreation when code changes
  lifecycle {
    ignore_changes = [
      source_code_hash,
      last_modified
    ]
  }
}

output "function_arn"  { value = aws_lambda_function.this.arn }
output "function_name" { value = aws_lambda_function.this.function_name }
