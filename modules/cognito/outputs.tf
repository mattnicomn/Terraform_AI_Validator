output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.this.arn
}

# Issuer URL used by JWT authorizer (matches your console JWKS base)
output "issuer_url" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "user_pool_client_id" {
  value = aws_cognito_user_pool_client.app.id
}

output "hosted_ui_domain" {
  value = aws_cognito_user_pool_domain.this.domain
}
