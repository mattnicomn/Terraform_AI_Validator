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
  description = "Allowed callback URLs (dedicated application origin)"
  type        = list(string)
}

variable "logout_urls" {
  description = "Allowed sign-out URLs (dedicated application origin)"
  type        = list(string)
  default     = []
}

variable "oauth_scopes" {
  description = "Allowed OAuth scopes for the app client."
  type        = list(string)
  default     = ["openid", "email", "profile"]
}

variable "mfa_configuration" {
  description = "MFA mode: OFF | OPTIONAL | ON. Design supports MFA; default OPTIONAL."
  type        = string
  default     = "OPTIONAL"
}

# NOTE: legacy inputs removed in the account-102 refactor:
#   - s3_access_iam_role_arn  (source-account 253 coupling: role/S3AmazonAccess)
#   - user_email              (seed user; users re-established separately)
# These are intentionally NOT present.
