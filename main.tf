####################
# S3 Buckets
####################
module "s3_source" {
  source                 = "./modules/s3"
  bucket_name            = local.s3_source_bucket
  bucket_owner_enforced  = true
  block_public_access    = true
  sse_sse_algorithm      = "AES256"
  cors_rules             = [] # none in CFN for source
  tags                   = local.common_tags
}

module "s3_destination" {
  source                 = "./modules/s3"
  bucket_name            = local.s3_destination_bucket
  bucket_owner_enforced  = true
  block_public_access    = true
  sse_sse_algorithm      = "AES256"
  cors_rules             = []
  tags                   = local.common_tags
}

module "s3_results" {
  source                 = "./modules/s3"
  bucket_name            = local.s3_results_bucket
  bucket_owner_preferred = true
  block_public_access    = true
  sse_sse_algorithm      = "AES256"
  cors_rules             = []
  tags                   = local.common_tags
}

# Frontend bucket (with CORS to CloudFront distro)
module "s3_frontend" {
  source                 = "./modules/s3"
  bucket_name            = local.frontend_bucket
  bucket_owner_preferred = true
  block_public_access    = true
  sse_sse_algorithm      = "AES256"
  cors_rules = [{
    allowed_methods = ["GET","HEAD","PUT","POST","DELETE"]
    allowed_origins = [var.frontend_allowed_origin]
    allowed_headers = ["*"]
    expose_headers  = ["ETag","x-amz-server-side-encryption"]
    max_age_seconds = 3000
  }]
  tags = local.common_tags
}

####################
# IAM (Lambda roles & inline policies)
####################
module "iam" {
  source = "./modules/iam"

  # SecurityDataTransferProcessor role (maps CFN IAMRoleSecurityDataTransferProcessorroleni1rwhqk)
  create_processor_role = true
  processor_role_name   = "SecurityDataTransferProcessor-role-ni1rwhqk"

  # BedrockPromptHandler role (maps CFN IAMRoleBedrockPromptHandlerrole461wkeeg)
  create_prompt_role = true
  prompt_role_name   = "BedrockPromptHandler-role-461wkeeg"

  s3_results_log_group_arn = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.lambda_processor_name}:*"

  # Optional: add the extra S3/SSM/KMS permissions from CFN
  attach_extra_prompt_policies = true

  tags = local.common_tags
}

data "aws_caller_identity" "current" {}

####################
# Lambda functions
####################
module "lambda_processor" {
  source           = "./modules/lambda"
  function_name    = local.lambda_processor_name
  role_arn         = module.iam.processor_role_arn
  runtime          = "python3.11"
  handler          = "lambda_function.lambda_handler"
  timeout          = 60
  memory_size      = 512
  architectures    = ["x86_64"]
  log_group_name   = "/aws/lambda/${local.lambda_processor_name}"
  package_type     = "Zip"
  code_s3_bucket   = var.processor_s3_bucket
  code_s3_key      = var.processor_s3_key
  code_s3_version  = var.processor_s3_object_ver
  code_kms_key_arn = var.processor_kms_key_arn
  tags             = local.common_tags
  environment = {
    variables = {
      SNS_TOPIC_ARN      = module.sns_alerts.topic_arn
      SOURCE_BUCKETS     = module.s3.names["source"]
      DESTINATION_BUCKETS= module.s3.names["destination"]
      RESULTS_BUCKET     = module.s3.names["results"]
}

module "lambda_prompt" {
  source           = "./modules/lambda"
  function_name    = local.lambda_prompt_name
  role_arn         = module.iam.prompt_role_arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  timeout          = 120
  memory_size      = 128
  architectures    = ["x86_64"]
  log_group_name   = "/aws/lambda/${local.lambda_prompt_name}"
  package_type     = var.prompt_image_uri != null ? "Image" : "Zip"
  image_uri        = var.prompt_image_uri
  code_s3_bucket   = var.prompt_s3_bucket
  code_s3_key      = var.prompt_s3_key
  code_s3_version  = var.prompt_s3_object_ver
  code_kms_key_arn = var.prompt_kms_key_arn
  tags             = local.common_tags
}


####################
# Lambda permissions for API Gateway (mirrors CFN)
# Lambda invoke permissions for each route
####################

resource "aws_lambda_permission" "apigw_invoke_prompt" {
  statement_id  = "AllowAPIGwInvokePrompt"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_prompt.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api.api_execution_arn}/*/*/BedrockPromptHandler"
}

resource "aws_lambda_permission" "apigw_invoke_scan_file" {
  statement_id  = "AllowAPIGwInvokeScanFile"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api.api_execution_arn}/*/POST/scan-file"
}
resource "aws_lambda_permission" "apigw_invoke_transfer_file" {
  statement_id  = "AllowAPIGwInvokeTransferFile"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api.api_execution_arn}/*/POST/transfer-file"
}
resource "aws_lambda_permission" "apigw_invoke_classification_report" {
  statement_id  = "AllowAPIGwInvokeClassificationReport"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api.api_execution_arn}/*/GET/classification-report"
}
resource "aws_lambda_permission" "apigw_invoke_scan_bucket" {
  statement_id  = "AllowAPIGwInvokeScanBucket"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api.api_execution_arn}/*/POST/scan-bucket"
}

####################
# CloudFront Distribution + OAC for frontend bucket
####################
module "cloudfront" {
  source            = "./modules/cloudfront"
  s3_bucket_domain  = module.s3_frontend.bucket_regional_domain_name
  oac_name          = "${local.frontend_bucket}.s3.${var.region}.amazonaws.com"
  default_origin_id = "${local.frontend_bucket}.s3.${var.region}.amazonaws.com"

  # Use AWS Managed policies via data-lookups (don’t recreate)
  cache_policy_names = ["Managed-CachingDisabled"] # matches CFN default used QY
  origin_request_policy_names = ["Managed-AllViewerExceptHostHeader"] # matches CFN PP
  response_headers_policy_id  = local.cloudfront_resp_headers_policy_id
  aliases                     = []  # add custom domain if needed
  tags                        = local.common_tags
}

# S3 bucket policy to allow CloudFront to GET (maps CFN S3BucketPolicyBedrockfrontend)
module "cloudfront_s3_policy" {
  source           = "./modules/cloudfront"
  create_s3_policy = true
  s3_bucket_arn    = module.s3_frontend.bucket_arn
  distribution_arn = module.cloudfront.distribution_arn
}

####################
# S3 Bucket Policy (source) to allow Lambda role access (maps CFN S3BucketPolicySecuritydatatransfers3source)
####################
resource "aws_s3_bucket_policy" "source_allow_lambda_role" {
  bucket = module.s3_source.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid:     "AllowLambdaRoleAccessToSource"
      Effect:  "Allow"
      Action:  "s3:*"
      Resource = "arn:aws:s3:::${local.s3_source_bucket}/*"
      Principal = {
        AWS = module.iam.processor_role_arn
      }
      Condition = null
    }]
  })
}

####################
# Bedrock Agent + Alias + Action Group (maps CFN BedrockAgent + BedrockAgentAlias + ActionGroup)
####################
module "bedrock" {
  count  = local.enable_bedrock_agent ? 1 : 0
  source = "./modules/bedrock"

  agent_name              = "SecurityDataTransferAgent"
  description             = "Validates transfers or hosted data between S3 buckets; scans for FedRAMP/PII/PHI"
  foundation_model        = var.bedrock_model_id
  agent_resource_role_arn = module.iam.bedrock_agent_role_arn
  instruction             = <<-EOT
    AGENT PURPOSE:
    Monitor and validate data transfers between S3 buckets, ensuring FedRAMP compliance and protecting PII/PHI...
    (trimmed for brevity—paste your full instruction from CFN here)
  EOT

  # Action group uses the Lambda processor and the OpenAPI payload you provided
  action_group_name   = "SecurityDataTransferActions"
  action_group_lambda = module.lambda_processor.function_arn
  openapi_payload     = file("${path.module}/openapi/security_data_transfer_api.yaml") # You can also inline the big YAML string

  aliases = [
    { name = "testdatascanner", version = "1" },
    { name = "AgentTestAlias",  version = "DRAFT" }
  ]

  tags = local.common_tags
}

module "cognito" {
  source = "./modules/cognito"

  region                 = var.aws_region
  user_pool_name         = "User pool - mo45tn"          # from console
  app_client_name        = "BedrockUserPool"             # from console
  domain_prefix          = "us-east-1qst1onmxw"          # use the prefix only
  callback_urls          = ["https://d11k4vck88gnf5.cloudfront.net/index.html"]
  logout_urls            = []                            # none set in console
  s3_access_iam_role_arn = "arn:aws:iam::253881689673:role/S3AmazonAccess"
  user_email             = "mattnicomn10@yahoo.com"      # optional; remove if you don’t want TF to manage users
}

# Your API Gateway module can continue to reference these:
#   module.cognito.issuer_url
#   module.cognito.user_pool_client_id


####################
# API Gateway (HTTP API) + routes to Lambdas
####################

# 2) API with routes; protect the ones you want
module "api_gateway" {
  source = "./modules/api_gateway"

  name                         = "BedrockAPI"
  cors_allow_origins           = [var.frontend_allowed_origin] # or ["*"] during dev
  cors_allow_methods           = ["OPTIONS","POST","GET"]
  cors_allow_headers           = ["authorization","content-type"]
  disable_execute_api_endpoint = false
  tags                         = local.common_tags

  routes = [
    { method = "POST", path = "/BedrockPromptHandler",   target_lambda_arn = module.lambda_prompt.function_arn },
    { method = "POST", path = "/scan-file",              target_lambda_arn = module.lambda_processor.function_arn },
    { method = "POST", path = "/transfer-file",          target_lambda_arn = module.lambda_processor.function_arn },
    { method = "GET",  path = "/classification-report",  target_lambda_arn = module.lambda_processor.function_arn },
    { method = "POST", path = "/scan-bucket",            target_lambda_arn = module.lambda_processor.function_arn },
  ]

  jwt_authorizer = {
    issuer   = module.cognito.issuer_url
    audience = [module.cognito.user_pool_client_id]
  }

  protected_routes = [
    "POST /transfer-file",
    "POST /scan-bucket",
    # add others as needed
  ]
}

output "http_api_url" {
  value = module.api_gateway.api_endpoint
}

# --- SNS (from earlier step) ---
module "sns_alerts" {
  source          = "./modules/sns_alerts"
  topic_name      = "SecurityDataTransferAlerts"
  email_endpoints = ["mattnicomn10@yahoo.com"]
  tags            = local.common_tags
}

# --- Lambda: SecurityDataTransferProcessor ---
module "lambda_processor" {
  source             = "./modules/lambda_sd_transfer"
  function_name      = "SecurityDataTransferProcessor"
  description        = "Scans S3 objects for PII/PHI/FedRAMP issues and manages transfers"
  source_file        = "${path.root}/lambda/SecurityDataTransferProcessor/lambda_function.py"

  sns_topic_arn      = module.sns_alerts.topic_arn
  source_bucket      = "securitydatatransfers3source"
  destination_bucket = "securitydatatransfers3destination"
  results_bucket     = "securitydatatransfers3results"

  # Optional extra env
  extra_env = {
    LOG_LEVEL = "INFO"
  }

  tags = local.common_tags
}

# --- Allow the lambda to publish to SNS (policy lives at root to avoid circular deps) ---
resource "aws_iam_policy" "sns_publish_security_alerts" {
  name   = "SNSPublishSecurityDataTransferAlerts"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["sns:Publish"],
      Resource = module.sns_alerts.topic_arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "processor_sns_publish_attach" {
  role       = module.lambda_processor.role_name
  policy_arn = aws_iam_policy.sns_publish_security_alerts.arn
}

# locals or variables you already have
locals {
  common_tags = {
    Project = "SecurityDataTransfer"
    Owner   = "CloudOps"
  }
}

# Assume you already have the Lambda module you built earlier and can reference its role ARN:
# module.lambda_processor.role_arn

module "s3" {
  source = "./modules/s3"

  # Logical keys (source/destination/results) -> concrete bucket names
  buckets = {
    source = {
      name          = "securitydatatransfers3source"
      ownership     = "BucketOwnerEnforced"   # matches CFN
      versioning    = false
      force_destroy = false
    }
    destination = {
      name          = "securitydatatransfers3destination"
      ownership     = "BucketOwnerEnforced"   # matches CFN
      versioning    = false
      force_destroy = false
    }
    results = {
      name          = "securitydatatransfers3results"
      ownership     = "BucketOwnerPreferred"  # matches CFN
      versioning    = false
      force_destroy = false
    }
  }

  source_key      = "source"
  destination_key = "destination"
  results_key     = "results"

  # OPTIONAL: attach bucket policies to allow Lambda role access.
  # If your account-level IAM (on the Lambda role) already grants access
  # and you don't have restrictive bucket policies, you can leave these empty.
  source_read_principals  = [module.lambda_processor.role_arn]
  dest_write_principals   = [module.lambda_processor.role_arn]
  results_write_principals= [module.lambda_processor.role_arn]

  tags = local.common_tags
}
