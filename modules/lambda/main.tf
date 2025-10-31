resource "aws_cloudwatch_log_group" "lg" {
  name              = var.log_group_name
  retention_in_days = 30
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

  dynamic "image_config" {
    for_each = var.package_type == "Image" ? [1] : []
    content {}
  }

  dynamic "image_uri" {
    for_each = var.package_type == "Image" ? [1] : []
    content = var.image_uri
  }

  dynamic "filename" {
    for_each = var.package_type == "Zip" && var.code_s3_bucket == null ? [1] : []
    content  = null # not used here
  }

  dynamic "s3_bucket" {
    for_each = var.package_type == "Zip" && var.code_s3_bucket != null ? [1] : []
    content  = var.code_s3_bucket
  }
  dynamic "s3_key" {
    for_each = var.package_type == "Zip" && var.code_s3_key != null ? [1] : []
    content  = var.code_s3_key
  }
  dynamic "s3_object_version" {
    for_each = var.package_type == "Zip" && var.code_s3_version != null ? [1] : []
    content  = var.code_s3_version
  }

  handler = var.handler
  runtime = var.runtime
}

output "function_arn"  { value = aws_lambda_function.this.arn }
output "function_name" { value = aws_lambda_function.this.function_name }
