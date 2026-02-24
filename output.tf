output "api_endpoint"      { value = module.api.api_endpoint }
output "api_id"            { value = module.api.api_id }
output "cloudfront_domain" { value = module.cloudfront.domain_name }
output "cloudfront_url"    { value = "https://${module.cloudfront.domain_name}" }
output "s3_frontend"       { value = module.s3_frontend.bucket_id }
output "lambda_processor"  { value = module.lambda_processor.function_name }
output "lambda_prompt"     { value = module.lambda_prompt.function_name }

output "cloudfront_public_key_id" {
  value       = module.cloudfront.public_key_id
  description = "CloudFront public key ID for signed URLs"
}

output "cognito_user_pool_id" {
  value       = module.cognito.user_pool_id
  description = "Cognito User Pool ID"
}

output "cognito_client_id" {
  value       = module.cognito.user_pool_client_id
  description = "Cognito App Client ID"
}

output "bedrock_agent_info" {
  value = {
    agent_id       = var.bedrock_agent_id
    agent_alias_id = var.bedrock_agent_alias_id
  }
  description = "Bedrock Agent configuration"
}
