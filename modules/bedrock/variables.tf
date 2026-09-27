variable "agent_name" { type = string }
variable "description" { type = string }
variable "foundation_model" { type = string }
variable "agent_resource_role_arn" { type = string }
variable "instruction" { type = string }

variable "action_group_name" { type = string }
variable "action_group_lambda" { type = string }
variable "openapi_payload" { type = string } # can be big

variable "aliases" {
  description = "Agent aliases. Only created when prepare_agent = true (a prepared version must exist)."
  type = list(object({
    name = string
  }))
  default = []
}

variable "prepare_agent" {
  type        = bool
  default     = false
  description = "Prepare the agent and create aliases. Requires model access enabled in the account (later AWS gate)."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "guardrail_identifier" {
  type        = string
  default     = null
  description = "Bedrock guardrail identifier for enhanced security"
}

variable "guardrail_version" {
  type        = string
  default     = "DRAFT"
  description = "Bedrock guardrail version"
}

variable "enable_prompt_override" {
  type        = bool
  default     = false
  description = "Enable prompt override configuration"
}
