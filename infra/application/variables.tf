# =============================================================================
# AI Validator — destination (account 102726256311) application variables
# Account-agnostic. No hard-coded source-account (253881689673) ARNs.
# No secrets. No personal emails as defaults.
# Phase 2 refactor (migration/ai-validator-102-refactor) — NOT YET APPLIED.
# =============================================================================

variable "region" {
  description = "AWS region for the AI Validator application."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment label (single AI application account for now)."
  type        = string
  default     = "prod"
}

variable "project" {
  description = "Project/name prefix for tagging and resource naming."
  type        = string
  default     = "ai-validator"
}

variable "owner" {
  description = "Owner tag value."
  type        = string
  default     = "platform"
}

variable "tags" {
  description = "Additional tags merged into common_tags."
  type        = map(string)
  default     = {}
}

# ── Application domain (dedicated AI Validator app) ──────────────────────────
variable "application_domain" {
  description = "Public application domain for the AI Validator (delegated subdomain in account 102)."
  type        = string
  default     = "ai.usmissionhero.com"
}

# ── Bedrock ──────────────────────────────────────────────────────────────────
# Phase 4A finding: anthropic.claude-haiku-4-5-20251001-v1:0 in account 102 is
# ACTIVE but supports INFERENCE_PROFILE ONLY (no ON_DEMAND). The agent's
# foundation_model must therefore reference the cross-region inference profile,
# not the bare model id. The bare model id is retained only to derive the
# underlying regional foundation-model ARNs the profile routes to (for IAM).
variable "bedrock_model_id" {
  description = "Underlying Bedrock foundation model id. NOT invocable ON_DEMAND in this account; used to derive the regional foundation-model ARNs the inference profile routes to."
  type        = string
  default     = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "bedrock_inference_profile_id" {
  description = "Cross-region inference profile id used as the agent's foundation_model (required because the underlying model is INFERENCE_PROFILE-only in account 102)."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "bedrock_inference_profile_regions" {
  description = "Regions the cross-region inference profile routes to. The agent role must be permitted to InvokeModel on the underlying foundation model in each of these regions."
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "enable_bedrock_agent" {
  description = "Whether to create the Bedrock agent + action group."
  type        = bool
  default     = true
}

# ── Cognito ────────────────────────────────────────────────────────────────
# Callback/logout target the dedicated application origin. Authorization-code
# flow only (no implicit). Public client (no secret). PreventUserExistenceErrors ON.
variable "cognito_callback_urls" {
  description = "Cognito allowed callback URLs (dedicated app origin)."
  type        = list(string)
  default     = ["https://ai.usmissionhero.com/", "https://ai.usmissionhero.com/callback"]
}

variable "cognito_logout_urls" {
  description = "Cognito allowed logout URLs (dedicated app origin)."
  type        = list(string)
  default     = ["https://ai.usmissionhero.com/"]
}

variable "cognito_oauth_scopes" {
  description = "OAuth scopes for the app client."
  type        = list(string)
  default     = ["openid", "email", "profile"]
}

variable "cognito_mfa_configuration" {
  description = "Cognito MFA mode. Design supports MFA; operational default OPTIONAL (documented in REFACTOR-NOTES)."
  type        = string
  default     = "OPTIONAL"
}

# ── Alerts (SNS) ─────────────────────────────────────────────────────────────
# No personal emails as defaults. Provide at apply time via tfvars/secure input.
variable "alert_email_endpoints" {
  description = "SNS alert subscription email endpoints (owner-provided at apply time; no default)."
  type        = list(string)
  default     = []
}

# ── Data / bucket naming (account-agnostic; account id appended in locals) ────
variable "source_bucket_basename" {
  description = "Base name for the source data bucket (account id appended in locals)."
  type        = string
  default     = "ai-validator-source"
}

variable "destination_bucket_basename" {
  description = "Base name for the destination data bucket."
  type        = string
  default     = "ai-validator-destination"
}

variable "results_bucket_basename" {
  description = "Base name for the results data bucket."
  type        = string
  default     = "ai-validator-results"
}

variable "frontend_bucket_basename" {
  description = "Base name for the private frontend hosting bucket."
  type        = string
  default     = "ai-validator-frontend"
}

# ── Lambda code package provenance (UNRESOLVED — see REFACTOR-NOTES) ─────────
# The repository does not contain an authoritative deployable code package for
# the two functions. These must be supplied at a later deployment gate.
variable "processor_s3_bucket" {
  description = "S3 bucket holding the Processor Lambda deployment package (deployment input; unresolved)."
  type        = string
  default     = null
}

variable "processor_s3_key" {
  description = "S3 key for the Processor Lambda package."
  type        = string
  default     = null
}

variable "prompt_s3_bucket" {
  description = "S3 bucket holding the PromptHandler Lambda deployment package (deployment input; unresolved)."
  type        = string
  default     = null
}

variable "prompt_s3_key" {
  description = "S3 key for the PromptHandler Lambda package."
  type        = string
  default     = null
}

# ── Frontend delivery staging gate ───────────────────────────────────────────
# Progression gate (false -> true), NOT a casual operational toggle.
#   false = Stage 1: create all core infra + child DNS zone + frontend origin
#           bucket + OAC + ACM certificate + ACM DNS validation record, but NOT
#           the ACM validation wait, CloudFront distribution, frontend bucket
#           policy, or application alias. A default apply MUST NOT block waiting
#           on external parent-zone NS delegation, so the default is false.
#   true  = Stage 2: enable ACM validation + CloudFront + bucket policy + alias.
#           Set true ONLY AFTER the parent usmissionhero.com zone (account 253,
#           website_infrastructure) publishes the NS delegation for the child
#           ai.usmissionhero.com zone and it resolves publicly.
# WARNING: switching back to false AFTER Stage 2 will PLAN DESTRUCTION of the
# delivery resources (CloudFront distribution, ACM validation, bucket policy,
# alias). Treat as a one-way progression gate.
variable "enable_frontend_delivery" {
  description = "Stage gate for frontend delivery. false = Stage 1 (no CloudFront/ACM-validation/alias/bucket-policy); true = Stage 2 (enable them) only after parent NS delegation is live. Progression gate false->true; reverting after Stage 2 plans destruction."
  type        = bool
  default     = false
}
