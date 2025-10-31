data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

variable "api_name" {
  type        = string
  default     = "SecurityDataTransferAPI"
  description = "Name for HTTP API."
}

# Optional CORS (adjust to your CloudFront domain or set to ["*"] for testing)
variable "cors_allow_origins" {
  type        = list(string)
  default     = ["*"]
  description = "CORS Allowed origins for the HTTP API."
}

resource "aws_apigatewayv2_api" "this" {
  name          = var.api_name
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["authorization", "content-type"]
    allow_methods = ["OPTIONS", "POST", "GET"]
    allow_origins = var.cors_allow_origins
    max_age       = 3600
    allow_credentials = false
  }
}

# One Lambda proxy integration reused by all routes
resource "aws_apigatewayv2_integration" "lambda_proxy" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
  integration_uri        = module.lambda_processor.function_arn
}

# ----------------------
# Routes → all proxy to the same Lambda integration
# ----------------------

resource "aws_apigatewayv2_route" "scan_file" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "POST /scan-file"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "transfer_file" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "POST /transfer-file"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "classification_report" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "GET /classification-report"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "scan_bucket" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "POST /scan-bucket"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

# Stage with auto deploy
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true
}

# ----------------------
# Lambda permissions (one per route/method for least privilege)
# SourceArn must be specific: arn:aws:execute-api:region:acct:api-id/*/METHOD/PATH
# Note: PATH in the ARN has no leading slash.
# ----------------------

locals {
  api_id = aws_apigatewayv2_api.this.id

  route_arns = {
    scan_file            = "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${local.api_id}/*/POST/scan-file"
    transfer_file        = "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${local.api_id}/*/POST/transfer-file"
    classification_report= "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${local.api_id}/*/GET/classification-report"
    scan_bucket          = "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${local.api_id}/*/POST/scan-bucket"
  }
}

resource "aws_lambda_permission" "scan_file" {
  statement_id  = "AllowInvokeByApiGatewayScanFile"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = local.route_arns.scan_file
}

resource "aws_lambda_permission" "transfer_file" {
  statement_id  = "AllowInvokeByApiGatewayTransferFile"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = local.route_arns.transfer_file
}

resource "aws_lambda_permission" "classification_report" {
  statement_id  = "AllowInvokeByApiGatewayClassificationReport"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = local.route_arns.classification_report
}

resource "aws_lambda_permission" "scan_bucket" {
  statement_id  = "AllowInvokeByApiGatewayScanBucket"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = local.route_arns.scan_bucket
}

# Handy outputs
output "http_api_id" {
  value = aws_apigatewayv2_api.this.id
}

output "http_api_execution_arn" {
  value = aws_apigatewayv2_api.this.execution_arn
}

output "http_api_invoke_base_url" {
  # For $default stage, base URL is just the API endpoint (no stage suffix)
  value = aws_apigatewayv2_api.this.api_endpoint
}
