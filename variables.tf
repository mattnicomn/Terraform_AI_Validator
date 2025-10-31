variable "region" { type = string  default = "us-east-1" }
variable "env"    { type = string  default = "dev" }
variable "project"{ type = string  default = "" }
variable "owner"  { type = string  default = "platform" }
variable "tags"   { type = map(string) default = {} }

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
variable "processor_s3_bucket"      { type = string }
variable "processor_s3_key"         { type = string }
variable "processor_s3_object_ver"  { type = string, default = null }
variable "processor_kms_key_arn"    { type = string, default = null }

variable "prompt_s3_bucket"      { type = string, default = null }
variable "prompt_s3_key"         { type = string, default = null }
variable "prompt_s3_object_ver"  { type = string, default = null }
variable "prompt_kms_key_arn"    { type = string, default = null }
variable "prompt_image_uri"      { type = string, default = null } # optional ECR image form

# Bedrock
variable "bedrock_model_id" {
  type    = string
  default = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "enable_bedrock_agent" { type = bool default = true }

# CloudFront public key (CFN had inline PEM; better to pass via var)
variable "cloudfront_public_key_pem" {
  type        = string
  description = "PEM of the CloudFront public key"
  default     = null
}
