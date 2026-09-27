# =============================================================================
# AI Validator — destination application locals
# Account-agnostic: account id comes from the live caller, never hard-coded.
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = var.region

  name_prefix = "${var.project}-${var.environment}"

  # Provider-safe tags for provider default_tags. MUST NOT contain any
  # AWS-provider-resolved value (e.g. data.aws_caller_identity account id),
  # otherwise the provider participates in a dependency cycle.
  provider_tags = merge({
    Project     = var.project
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "Terraform_AI_Validator"
  }, var.tags)

  # Full common tags for resource/module-level tagging (may include the
  # account id, which is safe outside provider configuration).
  common_tags = merge(local.provider_tags, {
    Account = local.account_id
  })

  # Globally-unique bucket names: basename + account id (destination account).
  source_bucket      = "${var.source_bucket_basename}-${local.account_id}"
  destination_bucket = "${var.destination_bucket_basename}-${local.account_id}"
  results_bucket     = "${var.results_bucket_basename}-${local.account_id}"
  frontend_bucket    = "${var.frontend_bucket_basename}-${local.account_id}"

  # Live API surface only (per Phase 0.5 discovery): PromptHandler route.
  lambda_processor_name = "SecurityDataTransferProcessor"
  lambda_prompt_name    = "BedrockPromptHandler"

  # Cognito Hosted UI domain prefix (new, dedicated; not the legacy prefix).
  cognito_domain_prefix = "ai-usmh-${local.account_id}"
}
