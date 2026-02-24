# SSM Parameter Store for CloudFront private key
# This is used by the Lambda function to sign CloudFront URLs

resource "aws_ssm_parameter" "cloudfront_private_key" {
  count = var.cloudfront_private_key_pem != null ? 1 : 0

  name        = "/cloudfront/private_key.pem"
  description = "CloudFront private key for signed URL generation"
  type        = "SecureString"
  value       = var.cloudfront_private_key_pem
  key_id      = var.ssm_kms_key_id

  tags = merge(local.common_tags, {
    Name = "CloudFront Private Key"
  })
}

# Grant Lambda access to the SSM parameter
resource "aws_iam_policy" "lambda_ssm_cloudfront_key" {
  count = var.cloudfront_private_key_pem != null ? 1 : 0

  name        = "LambdaSSMCloudFrontKeyAccess"
  description = "Allow Lambda to read CloudFront private key from SSM"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = aws_ssm_parameter.cloudfront_private_key[0].arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.ssm_kms_key_id != null ? "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/${var.ssm_kms_key_id}" : "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ssm.${var.region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_prompt_ssm" {
  count = var.cloudfront_private_key_pem != null ? 1 : 0

  role       = module.iam.prompt_role_name
  policy_arn = aws_iam_policy.lambda_ssm_cloudfront_key[0].arn
}
