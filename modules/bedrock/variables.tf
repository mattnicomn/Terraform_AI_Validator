variable "agent_name"              { type = string }
variable "description"             { type = string }
variable "foundation_model"        { type = string }
variable "agent_resource_role_arn" { type = string }
variable "instruction"             { type = string }

variable "action_group_name"   { type = string }
variable "action_group_lambda" { type = string }
variable "openapi_payload"     { type = string } # can be big

variable "aliases" {
  type = list(object({
    name    = string
    version = string
  }))
  default = []
}

variable "tags" { type = map(string) default = {} }
