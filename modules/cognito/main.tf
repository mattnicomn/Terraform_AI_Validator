terraform {
  required_version = ">= 1.7.0"
}

# ── Cognito User Pool (destination account 102) ──────────────────────────────
resource "aws_cognito_user_pool" "this" {
  name = var.user_pool_name

  # Design supports MFA (default OPTIONAL); operational enrollment documented
  # in REFACTOR-NOTES. When MFA is OPTIONAL/ON, a software token config is set.
  mfa_configuration = var.mfa_configuration

  dynamic "software_token_mfa_configuration" {
    for_each = var.mfa_configuration == "OFF" ? [] : [1]
    content {
      enabled = true
    }
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── Hosted UI domain (dedicated, new prefix) ─────────────────────────────────
resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

# ── User Pool Client (public; authorization-code flow only) ──────────────────
resource "aws_cognito_user_pool_client" "app" {
  name         = var.app_client_name
  user_pool_id = aws_cognito_user_pool.this.id

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"] # authorization-code only; implicit removed
  allowed_oauth_scopes                 = var.oauth_scopes
  supported_identity_providers         = ["COGNITO"]

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  generate_secret = false # public client

  prevent_user_existence_errors = "ENABLED"

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  access_token_validity  = 60 # minutes
  id_token_validity      = 60 # minutes
  refresh_token_validity = 5  # days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  lifecycle {
    prevent_destroy = true
  }
}
