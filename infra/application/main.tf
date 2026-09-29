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

  create_bedrock_agent_role = true
  bedrock_agent_role_name   = "${local.name_prefix}-bedrock-agent-role"

  processor_function_name = local.lambda_processor_name
  prompt_function_name    = local.lambda_prompt_name

  source_bucket_arn      = "arn:aws:s3:::${local.source_bucket}"
  destination_bucket_arn = "arn:aws:s3:::${local.destination_bucket}"
  results_bucket_arn     = "arn:aws:s3:::${local.results_bucket}"
  alerts_topic_arn       = module.sns_alerts.topic_arn

  # Phase 4B: the agent's foundation_model is a CROSS-REGION inference profile
  # (the underlying model is INFERENCE_PROFILE-only in account 102). The agent
  # role must be allowed to InvokeModel on the account-scoped inference-profile
  # ARN AND on the underlying foundation-model ARN in each region the profile
  # routes to (foundation-model ARNs are account-less/region-scoped).
  bedrock_model_arns = concat(
    ["arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_inference_profile_id}"],
    [for r in var.bedrock_inference_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_model_id}"]
  )

  # RESOLVED (Phase 3): PromptHandler invokes the Bedrock AGENT
  # (bedrock-agent-runtime:invoke_agent -> bedrock:InvokeAgent), scoped to this
  # account/region's agent aliases. New destination agent IDs are created by
  # the bedrock module; scope to the account/region agent-alias pattern.
  agent_alias_arn_wildcard = "arn:aws:bedrock:${local.region}:${local.account_id}:agent-alias/*"

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
  # Agent id/alias come from the bedrock module. Until the agent is prepared
  # (prepare_agent=true, gated on model access), the alias id is empty and the
  # handler fails clearly at runtime — no fake defaults.
  environment_variables = {
    BEDROCK_AGENT_ID       = try(module.bedrock[0].agent_id, "")
    BEDROCK_AGENT_ALIAS_ID = try(module.bedrock[0].agent_alias_id == null ? "" : module.bedrock[0].agent_alias_id, "")
    ALLOWED_ORIGIN         = "https://${var.application_domain}"
  }

  tags = local.common_tags
}

# Allow the Bedrock agent to invoke the Processor (action-group executor path).
# This is the CORRECT side for the action-group invocation relationship: the
# permission lives on the Lambda (bedrock.amazonaws.com principal), NOT as
# lambda:InvokeFunction on the agent role.
resource "aws_lambda_permission" "bedrock_invoke_processor" {
  statement_id   = "AllowBedrockAgentInvokeProcessor"
  action         = "lambda:InvokeFunction"
  function_name  = module.lambda_processor.function_name
  principal      = "bedrock.amazonaws.com"
  source_account = local.account_id
  source_arn     = "arn:aws:bedrock:${local.region}:${local.account_id}:agent/*"
}

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

  # LIVE API surface only. Processor is NOT exposed via API (invoked by agent).
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

# ── Bedrock agent + action group (parameterized model) ───────────────────────
module "bedrock" {
  count  = var.enable_bedrock_agent ? 1 : 0
  source = "../../modules/bedrock" # EXISTING module (reused)

  agent_name  = "${local.name_prefix}-agent"
  description = "Validates/scans S3 data transfers for FedRAMP/PII/PHI (destination account ${local.account_id})."
  # Phase 4A finding: the underlying model is INFERENCE_PROFILE-only in 102, so
  # the agent's foundation_model must be the cross-region inference profile id,
  # NOT the bare model id. (bedrock_model_id is still used to derive the IAM
  # foundation-model ARNs the profile routes to — see module.iam above.)
  foundation_model        = var.bedrock_inference_profile_id
  agent_resource_role_arn = module.iam.bedrock_agent_role_arn

  # RESOLVED (Phase 3): authoritative agent instruction recovered from the live
  # agent and stored as non-secret repo config. Bucket names generalized (no
  # account-specific/source values baked in).
  instruction = file("${path.module}/../../agent/instruction.txt")

  action_group_name   = "SecurityDataTransferActions"
  action_group_lambda = module.lambda_processor.function_arn
  openapi_payload     = file("${path.module}/../../openapi/security_data_transfer_api.yaml")

  # prepare_agent + aliases gated on model access enablement (later AWS gate).
  prepare_agent = false
  aliases       = [{ name = "prod" }]

  tags = local.common_tags
}

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
