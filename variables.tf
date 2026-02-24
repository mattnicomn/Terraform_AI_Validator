variable "region" { 
  type    = string
  default = "us-east-1"
}

variable "env" { 
  type    = string
  default = "dev"
}

variable "project" { 
  type    = string
  default = ""
}

variable "owner" { 
  type    = string
  default = "platform"
}

variable "tags" { 
  type    = map(string)
  default = {}
}

# Frontend CORS origin (from CFN)
variable "frontend_allowed_origin" {
  type    = string
  default = "https://d11k4vck88gnf5.cloudfront.net"
}

# CloudFront Response Headers Policy Id used in CFN default behavior
variable "cloudfront_resp_headers_policy_id" {
  type = string
  # default set blank; pass your 60669652-... via tfvars if you need the same one
  default = ""
}

# Lambda code sources (parity with CFN’s parameters)
variable "processor_s3_bucket" { 
  type = string
}
variable "processor_s3_key" { 
  type = string
}
variable "processor_s3_object_ver" { 
  type    = string
  default = null
}
variable "processor_kms_key_arn" { 
  type    = string
  default = null
}

variable "prompt_s3_bucket" { 
  type    = string
  default = null
}
variable "prompt_s3_key" { 
  type    = string
  default = null
}
variable "prompt_s3_object_ver" { 
  type    = string
  default = null
}
variable "prompt_kms_key_arn" { 
  type    = string
  default = null
}
variable "prompt_image_uri" { 
  type        = string
  default     = null
  description = "Optional ECR image form"
}

# Bedrock
variable "bedrock_model_id" {
  type    = string
  default = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "enable_bedrock_agent" { 
  type    = bool
  default = true
}

# CloudFront public key (CFN had inline PEM; better to pass via var)
variable "cloudfront_public_key_pem" {
  type        = string
  description = "PEM-encoded CloudFront public key for signed URLs"
  default     = null
  sensitive   = true
}

variable "bedrock_agent_id" {
  type        = string
  description = "Bedrock Agent ID"
  default     = "NNKUTQQWKP"
}

variable "bedrock_agent_alias_id" {
  type        = string
  description = "Bedrock Agent Alias ID"
  default     = "GVM7ZZPOOM"
}

variable "cloudfront_private_key_pem" {
  type        = string
  description = "PEM-encoded CloudFront private key for signed URL generation (stored in SSM)"
  default     = null
  sensitive   = true
}

variable "ssm_kms_key_id" {
  type        = string
  description = "KMS key ID for SSM parameter encryption"
  default     = null
}

variable "quarantine_bucket" {
  type    = string
  default = "securitydatatransfers3quarantine"
}

variable "log_group_kms_key_id" {
  type        = string
  default     = null
  description = "KMS key ID for CloudWatch Logs encryption"
}

variable "enable_bedrock_guardrails" {
  type        = bool
  default     = false
  description = "Enable Bedrock guardrails for enhanced security"
}

variable "bedrock_guardrail_identifier" {
  type        = string
  default     = null
  description = "Bedrock guardrail identifier"
}

variable "bedrock_guardrail_version" {
  type        = string
  default     = "DRAFT"
  description = "Bedrock guardrail version"
}
