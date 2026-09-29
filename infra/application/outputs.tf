# =============================================================================
# AI Validator — destination application outputs
# =============================================================================

output "account_id" {
  description = "Destination account id (live caller)."
  value       = local.account_id
}

output "api_endpoint" {
  description = "HTTP API endpoint."
  value       = module.api_gateway.api_endpoint
}

output "api_id" {
  value = module.api_gateway.api_id
}

output "cognito_user_pool_id" {
  value = module.cognito.user_pool_id
}

output "cognito_client_id" {
  value = module.cognito.user_pool_client_id
}

output "cognito_issuer_url" {
  value = module.cognito.issuer_url
}

output "data_buckets" {
  value = {
    source      = local.source_bucket
    destination = local.destination_bucket
    results     = local.results_bucket
  }
}

output "frontend_bucket" {
  value = local.frontend_bucket
}

output "frontend_cloudfront_domain" {
  description = "CloudFront domain for the AI Validator frontend."
  value       = module.frontend.cloudfront_domain
}

output "application_domain" {
  value = var.application_domain
}

output "dns_zone_id" {
  description = "Route53 hosted zone id for the delegated ai.usmissionhero.com zone (account 102)."
  value       = module.dns.zone_id
}

output "dns_name_servers" {
  description = "Name servers for the delegated zone (provide to website_infrastructure for the parent NS delegation record)."
  value       = module.dns.name_servers
}

output "bedrock_model_id" {
  description = "Underlying foundation model id (INFERENCE_PROFILE-only in this account; not invoked directly)."
  value       = var.bedrock_model_id
}

output "bedrock_inference_profile_id" {
  description = "Cross-region inference profile id the PromptHandler invokes via bedrock-runtime Converse."
  value       = var.bedrock_inference_profile_id
}
