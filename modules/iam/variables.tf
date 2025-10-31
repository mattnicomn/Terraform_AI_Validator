variable "create_processor_role"         { type = bool default = true }
variable "processor_role_name"           { type = string default = "SecurityDataTransferProcessor-role" }

variable "create_prompt_role"            { type = bool default = true }
variable "prompt_role_name"              { type = string default = "BedrockPromptHandler-role" }

variable "attach_extra_prompt_policies"  { type = bool default = true }

# For logging policy example
variable "s3_results_log_group_arn"      { type = string default = null }

variable "tags" { type = map(string) default = {} }
