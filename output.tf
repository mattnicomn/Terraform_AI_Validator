output "api_endpoint"      { value = module.api.api_endpoint }
output "api_id"            { value = module.api.api_id }
output "cloudfront_domain" { value = module.cloudfront.domain_name }
output "s3_frontend"       { value = module.s3_frontend.bucket_id }
output "lambda_processor"  { value = module.lambda_processor.function_name }
output "lambda_prompt"     { value = module.lambda_prompt.function_name }
