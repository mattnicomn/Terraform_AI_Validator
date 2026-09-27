# =============================================================================
# AI Validator IAM module — least-privilege (account 102 destination).
# All resource references are destination-scoped inputs; no source-account
# (253) ARNs, no wildcard-account ARNs, no broad managed policies.
# =============================================================================

variable "create_processor_role" {
  type    = bool
  default = true
}

variable "processor_role_name" {
  type = string
}

variable "create_prompt_role" {
  type    = bool
  default = true
}

variable "prompt_role_name" {
  type = string
}

variable "create_bedrock_agent_role" {
  type    = bool
  default = true
}

variable "bedrock_agent_role_name" {
  type = string
}

# ── Least-privilege scoping inputs (evidence-derived) ────────────────────────
variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "processor_function_name" {
  type        = string
  description = "Processor Lambda function name (for its own log group ARN)."
}

variable "prompt_function_name" {
  type        = string
  description = "PromptHandler Lambda function name (for its own log group ARN)."
}

variable "processor_function_arn" {
  type        = string
  description = "Processor Lambda ARN (Bedrock-agent invoke target; used only if agent role needs it — see note)."
  default     = null
}

variable "source_bucket_arn" {
  type = string
}

variable "destination_bucket_arn" {
  type = string
}

variable "results_bucket_arn" {
  type = string
}

variable "alerts_topic_arn" {
  type = string
}

variable "bedrock_model_arns" {
  type        = list(string)
  description = "ARNs the AGENT is permitted to bedrock:InvokeModel. For a cross-region inference profile this MUST include the inference-profile ARN plus the underlying foundation-model ARN in each region the profile routes to. Used by the agent role, not the prompt role."
}

# RESOLVED (Phase 3 recovered source): PromptHandler calls
# bedrock-agent-runtime:invoke_agent -> IAM action bedrock:InvokeAgent, scoped to
# the destination agent alias. It does NOT call bedrock:InvokeModel.
variable "agent_alias_arn_wildcard" {
  type        = string
  description = "Resource ARN (pattern) for bedrock:InvokeAgent by PromptHandler, scoped to the destination agent's aliases. Provided by the root once the agent exists; use an agent-alias ARN pattern for this account/region."
}

variable "tags" {
  type    = map(string)
  default = {}
}
