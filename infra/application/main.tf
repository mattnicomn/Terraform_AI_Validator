# =============================================================================
# AI Validator — destination application composition (account 102726256311)
# Live-source-derived runtime only. Account-agnostic. Least-privilege IAM.
# Live API surface only: POST /BedrockPromptHandler (+ OPTIONS/CORS).
# NO historical CloudFront/bedrockfrontend/portfolio assets.
# NO SSM CloudFront signing keys (removed from required initial architecture).
# Phase 2 refactor — NOT YET APPLIED. No terraform init/plan/apply.
#
# NOTE: module wiring below is the target composition. Module source dirs marked
# NEW must be authored before init; EXISTING modules are reused with
# least-privilege inputs. See REFACTOR-NOTES.md for the module status matrix.
# =============================================================================

# ── Data buckets (source / destination / results) ───────────────────────────
# Recreate-empty now; data COPY is a separate later gate (frozen owner decision).
module "data_buckets" {
  source = "../../modules/s3" # EXISTING module (reused)

  buckets = {
    source = {
      name          = local.source_bucket
      ownership     = "BucketOwnerEnforced"
      versioning    = false
      force_destroy = false
    }
    destination = {
      name          = local.destination_bucket
      ownership     = "BucketOwnerEnforced"
      versioning    = false
      force_destroy = false
    }
    results = {
      name          = local.results_bucket
      ownership     = "BucketOwnerPreferred"
      versioning    = false # PROPOSED enhancement: enable on results for audit (see REFACTOR-NOTES)
      force_destroy = false
    }
  }

  source_key      = "source"
  destination_key = "destination"
  results_key     = "results"

  # Least-privilege: bind bucket access to the destination processor role only.
  source_read_principals   = [module.iam.processor_role_arn]
  dest_write_principals    = [module.iam.processor_role_arn]
  results_write_principals = [module.iam.processor_role_arn]

  tags = local.common_tags
}

# ── Least-privilege IAM ──────────────────────────────────────────────────────
module "iam" {
  source = "../../modules/iam" # REFACTORED to least-privilege (Phase 2B)

  region     = local.region
  account_id = local.account_id

  create_processor_role = true
  processor_role_name   = "${local.name_prefix}-processor-role"

  create_prompt_role = true
  prompt_role_name   = "${local.name_prefix}-prompt-role"

  # Recovery architecture: Bedrock Agents Classic is unavailable in this
  # account. PromptHandler calls bedrock-runtime Converse directly and invokes
  # the Processor Lambda itself, so no Bedrock agent execution role is needed.
  create_bedrock_agent_role = false

  processor_function_name = local.lambda_processor_name
  prompt_function_name    = local.lambda_prompt_name

  source_bucket_arn      = "arn:aws:s3:::${local.source_bucket}"
  destination_bucket_arn = "arn:aws:s3:::${local.destination_bucket}"
  results_bucket_arn     = "arn:aws:s3:::${local.results_bucket}"
  alerts_topic_arn       = module.sns_alerts.topic_arn

  # PromptHandler execution role permissions for direct Converse:
  #  - bedrock:InvokeModel on the cross-region inference profile ARN plus the
  #    underlying foundation-model ARN in each region the profile routes to
  #    (foundation-model ARNs are account-less/region-scoped).
  #  - lambda:InvokeFunction scoped to the Processor Lambda ARN only (tool
  #    dispatch). No aws_lambda_permission is used for this same-account,
  #    identity-based invocation.
  bedrock_model_arns = concat(
    ["arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_inference_profile_id}"],
    [for r in var.bedrock_inference_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_model_id}"]
  )
  processor_function_arn = "arn:aws:lambda:${local.region}:${local.account_id}:function:${local.lambda_processor_name}"

  tags = local.common_tags
}

# ── Lambda functions (code package provenance UNRESOLVED — see REFACTOR-NOTES) ─
module "lambda_processor" {
  source         = "../../modules/lambda" # EXISTING module (reused)
  function_name  = local.lambda_processor_name
  role_arn       = module.iam.processor_role_arn
  runtime        = "python3.11"
  handler        = "lambda_function.lambda_handler"
  timeout        = 60
  memory_size    = 512
  architectures  = ["x86_64"]
  log_group_name = "/aws/lambda/${local.lambda_processor_name}"
  package_type   = "Zip"
  code_s3_bucket = var.processor_s3_bucket # unresolved deployment input
  code_s3_key    = var.processor_s3_key

  # Destination runtime config consumed by src/processor/lambda_function.py.
  environment_variables = {
    SOURCE_BUCKET      = local.source_bucket
    DESTINATION_BUCKET = local.destination_bucket
    RESULTS_BUCKET     = local.results_bucket
    ALERTS_TOPIC_ARN   = module.sns_alerts.topic_arn
  }

  tags = local.common_tags
}

module "lambda_prompt" {
  source         = "../../modules/lambda" # EXISTING module (reused)
  function_name  = local.lambda_prompt_name
  role_arn       = module.iam.prompt_role_arn
  runtime        = "python3.12"
  handler        = "lambda_function.lambda_handler" # matches LIVE (not repo's BedrockPromptHandler.lambda_handler)
  timeout        = 120
  memory_size    = 128
  architectures  = ["x86_64"]
  log_group_name = "/aws/lambda/${local.lambda_prompt_name}"
  package_type   = "Zip"
  code_s3_bucket = var.prompt_s3_bucket # unresolved deployment input
  code_s3_key    = var.prompt_s3_key

  # Destination runtime config consumed by src/prompt_handler/lambda_function.py.
  # Direct Converse architecture: the handler calls bedrock-runtime Converse on
  # the cross-region inference profile and dispatches tools to the Processor
  # Lambda by name. No Bedrock agent id/alias.
  environment_variables = {
    BEDROCK_INFERENCE_PROFILE_ID = var.bedrock_inference_profile_id
    PROCESSOR_FUNCTION_NAME      = local.lambda_processor_name
    ALLOWED_ORIGIN               = "https://${var.application_domain}"
  }

  tags = local.common_tags
}

# Recovery architecture note: there is NO Bedrock-agent -> Processor Lambda
# permission. The Processor is invoked directly by the PromptHandler execution
# role (lambda:InvokeFunction in module.iam, scoped to the Processor ARN), so no
# resource-based aws_lambda_permission is required for that same-account call.

# NOTE: API Gateway -> PromptHandler invoke permission is created INSIDE
# modules/api_gateway (aws_lambda_permission.invoke_by_apigw, per route). Do NOT
# duplicate it here (would collide on statement_id / create a duplicate grant).

# ── Cognito (NEW destination pool/client) ────────────────────────────────────
module "cognito" {
  source = "../../modules/cognito" # EXISTING module — MUST be refactored (auth-code only, MFA-capable, no legacy inputs)

  region          = local.region
  user_pool_name  = "${local.name_prefix}-users"
  app_client_name = "${local.name_prefix}-app"
  domain_prefix   = local.cognito_domain_prefix

  callback_urls     = var.cognito_callback_urls
  logout_urls       = var.cognito_logout_urls
  oauth_scopes      = var.cognito_oauth_scopes
  mfa_configuration = var.cognito_mfa_configuration
  # authorization-code flow only; implicit removed (module refactor).
  # No s3_access_iam_role_arn (legacy 253 coupling removed).
  # No seed user_email (users re-established separately).
}

# ── HTTP API (live surface only) ─────────────────────────────────────────────
module "api_gateway" {
  source = "../../modules/api_gateway" # EXISTING module (reused)

  name                         = "${local.name_prefix}-api"
  cors_allow_origins           = ["https://${var.application_domain}"]
  cors_allow_methods           = ["OPTIONS", "POST"]
  cors_allow_headers           = ["authorization", "content-type"]
  disable_execute_api_endpoint = false
  tags                         = local.common_tags

  # LIVE API surface only. The Processor is not exposed via the API; it is
  # invoked directly by the PromptHandler Lambda during Converse tool dispatch.
  routes = [
    { method = "POST", path = "/BedrockPromptHandler", target_lambda_arn = module.lambda_prompt.function_arn },
  ]

  jwt_authorizer = {
    issuer   = module.cognito.issuer_url
    audience = [module.cognito.user_pool_client_id]
  }

  protected_routes = [
    "POST /BedrockPromptHandler",
  ]
}

# ── SNS alerts ───────────────────────────────────────────────────────────────
module "sns_alerts" {
  source          = "../../modules/sns_alerts" # EXISTING module (reused)
  topic_name      = "SecurityDataTransferAlerts"
  email_endpoints = var.alert_email_endpoints # owner-provided; no personal default
  tags            = local.common_tags
}

# ── Bedrock ──────────────────────────────────────────────────────────────────
# Recovery architecture: Amazon Bedrock Agents Classic is closed to new
# customers and cannot be created in this destination account. The application
# no longer provisions a Bedrock agent / action group. Instead, PromptHandler
# calls bedrock-runtime Converse directly on the inference profile
# (var.bedrock_inference_profile_id) and dispatches tools to the Processor
# Lambda (see modules/prompt handler + module.iam). modules/bedrock is now
# obsolete and unwired.

# ── Frontend (NEW): private S3 + CloudFront + OAC + ACM for ai.usmissionhero.com
module "frontend" {
  source = "../../modules/frontend" # NEW module (authored in Phase 2)

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  application_domain = var.application_domain
  bucket_name        = local.frontend_bucket
  hosted_zone_id     = module.dns.zone_id # ACM validation + alias in the DELEGATED zone
  # Stage gate: false creates Stage-1 frontend resources (bucket, OAC, cert,
  # validation record) but NOT the ACM validation wait / CloudFront / alias /
  # bucket policy. Flip to true only after parent NS delegation is live.
  enable_frontend_delivery = var.enable_frontend_delivery
  tags                     = local.common_tags
}

# ── Route53 DELEGATED zone (102 owns ai.usmissionhero.com only) ──────────────
# Parent usmissionhero.com zone (account 253) is owned by website_infrastructure
# and holds the NS delegation. This module MUST NOT manage the parent zone.
module "dns" {
  source = "../../modules/dns" # NEW module (authored in Phase 2)

  application_domain = var.application_domain # ai.usmissionhero.com
  tags               = local.common_tags
}
