locals {
  project             = var.project != "" ? var.project : "security-data-transfer"
  env                 = var.env
  common_tags = merge({
    Project = local.project
    Env     = local.env
    Owner   = var.owner
  }, var.tags)

  # Names (aligning to CFN where practical)
  s3_source_bucket      = "securitydatatransfers3source"
  s3_destination_bucket = "securitydatatransfers3destination"
  s3_results_bucket     = "securitydatatransfers3results"
  frontend_bucket       = "bedrockfrontend"

  lambda_processor_name = "SecurityDataTransferProcessor"
  lambda_prompt_name    = "BedrockPromptHandler"

  cloudfront_resp_hdrs_policy_id = var.cloudfront_resp_headers_policy_id # you supplied in CFN: 60669652-455b-4ae9-85a4-c4c02393f86c

  # Feature toggles
  enable_bedrock_agent = var.enable_bedrock_agent
}
