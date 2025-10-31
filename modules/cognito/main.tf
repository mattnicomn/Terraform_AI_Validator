terraform {
  required_version = ">= 1.5.0"
}

# ── Cognito User Pool ────────────────────────────────────────────────────────────
resource "aws_cognito_user_pool" "this" {
  name = var.user_pool_name

  # Basic security / token settings to match console
  mfa_configuration = "OFF"

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = false
    require_uppercase = true
    temporary_password_validity_days = 7
  }

  # Token validity windows
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  # Prevent accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}

# ── User Pool Client ────────────────────────────────────────────────────────────
resource "aws_cognito_user_pool_client" "app" {
  name         = var.app_client_name
  user_pool_id = aws_cognito_user_pool.this.id

  # OAuth / grants to match your config
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows   = ["code", "implicit"]
  allowed_oauth_scopes  = [
    "aws.cognito.signin.user.admin",
    "email",
    "openid",
    "phone",
    "profile"
  ]
  supported_identity_providers = ["COGNITO"]

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  generate_secret = false

  # Auth flows
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  access_token_validity  = 60   # minutes
  id_token_validity      = 60   # minutes
  refresh_token_validity = 5    # days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ──
