variable "region" {
  description = "AWS region"
  type        = string
}

variable "user_pool_name" {
  description = "Cognito User Pool name"
  type        = string
}

variable "app_client_name" {
  description = "Cognito App Client name"
  type        = string
}

variable "domain_prefix" {
  description = "Cognito hosted UI domain prefix (not the full URL)"
  type        = string
}

variable "callback_urls" {
  description = "Allowed callback URLs"
  type        = list(string)
}

variable "logout_urls" {
  description = "Allowed sign-out URLs"
  type        = list(string)
  default     = []
}

variable "s3_access_iam_role_arn" {
  description = "IAM Role ARN mapped to S3accessUser group"
  type        = string
}

variable "user_email" {
  description = "Seed user email (optional if you manage users outside Terraform)"
  type        = string
  default     = ""
}
