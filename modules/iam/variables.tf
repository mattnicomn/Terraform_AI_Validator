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
  default = false # recovery architecture: no Bedrock Agents Classic role
}

variable "bedrock_agent_role_name" {
  type        = string
  default     = null # only required when create_bedrock_agent_role = true
  description = "Name for the optional/legacy Bedrock agent execution role. Only used when create_bedrock_agent_role = true."
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
  description = "Processor Lambda ARN. When set, the PromptHandler role is granted lambda:InvokeFunction scoped to this ARN for Converse tool dispatch."
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
  description = "ARNs permitted for bedrock:InvokeModel by the PromptHandler role (direct Converse). For a cross-region inference profile this MUST include the inference-profile ARN plus the underlying foundation-model ARN in each region the profile routes to. (Also consumed by the optional/legacy bedrock_agent role when create_bedrock_agent_role = true.)"
}

# Recovery architecture: PromptHandler calls bedrock-runtime Converse directly
# (bedrock:InvokeModel on var.bedrock_model_arns) and invokes the Processor
# Lambda (lambda:InvokeFunction on var.processor_function_arn). There is no
# bedrock:InvokeAgent and no agent-alias resource; the former
# agent_alias_arn_wildcard input has been removed.

variable "tags" {
  type    = map(string)
  default = {}
}
