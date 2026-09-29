# =============================================================================
# AI Validator IAM — least-privilege destination roles (account 102).
# No AdministratorAccess / *FullAccess / wildcard-account ARNs.
# All ARNs derive from destination-scoped inputs.
# =============================================================================

locals {
  processor_log_arn = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.processor_function_name}:*"
  prompt_log_arn    = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.prompt_function_name}:*"
}

# ── Processor role ───────────────────────────────────────────────────────────
resource "aws_iam_role" "processor" {
  count = var.create_processor_role ? 1 : 0
  name  = var.processor_role_name
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "processor" {
  count = var.create_processor_role ? 1 : 0
  name  = "processor-least-privilege"
  role  = aws_iam_role.processor[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.processor_log_arn
      },
      {
        Sid      = "SourceRead"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectTagging"]
        Resource = "${var.source_bucket_arn}/*"
      },
      {
        Sid      = "SourceList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = var.source_bucket_arn
      },
      {
        Sid      = "DestResultsWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging", "s3:GetObject"]
        Resource = ["${var.destination_bucket_arn}/*", "${var.results_bucket_arn}/*"]
      },
      {
        Sid      = "DestResultsList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [var.destination_bucket_arn, var.results_bucket_arn]
      },
      {
        Sid      = "AlertsPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.alerts_topic_arn
      },
      {
        # Recovered source calls only detect_pii_entities (NOT ContainsPiiEntities).
        Sid      = "ComprehendPII"
        Effect   = "Allow"
        Action   = ["comprehend:DetectPiiEntities"]
        Resource = "*" # Comprehend detect actions do not support resource-level scoping
      }
    ]
  })
}

# ── PromptHandler role ───────────────────────────────────────────────────────
# Bedrock call path NOT_VERIFIED — no Bedrock permission granted by default.
resource "aws_iam_role" "prompt" {
  count = var.create_prompt_role ? 1 : 0
  name  = var.prompt_role_name
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

# PromptHandler least-privilege (recovery architecture — direct Converse):
#  - own log group
#  - bedrock:InvokeModel on the cross-region inference profile ARN + the
#    underlying regional foundation-model ARNs it routes to
#  - lambda:InvokeFunction scoped ONLY to the Processor Lambda ARN (tool
#    dispatch). No bedrock:InvokeAgent (Agents Classic dropped). Legacy
#    SSM/CloudFront-signing permissions remain intentionally ABSENT.
resource "aws_iam_role_policy" "prompt" {
  count = var.create_prompt_role ? 1 : 0
  name  = "prompt-least-privilege"
  role  = aws_iam_role.prompt[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "OwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.prompt_log_arn
      },
      {
        Sid      = "BedrockInvokeModel"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = var.bedrock_model_arns
      }
      ], var.processor_function_arn == null ? [] : [
      {
        Sid      = "InvokeProcessorForToolDispatch"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = var.processor_function_arn
      }
    ])
  })
}

# ── Bedrock agent resource role ──────────────────────────────────────────────
# The agent role needs to invoke the chosen model. It does NOT need
# lambda:InvokeFunction for the action group: the action-group invocation is
# authorized on the LAMBDA side via an aws_lambda_permission for the
# bedrock.amazonaws.com principal (created in the application root). Model
# access enablement is a separate later gate.
resource "aws_iam_role" "bedrock_agent" {
  count = var.create_bedrock_agent_role ? 1 : 0
  name  = var.bedrock_agent_role_name
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "bedrock_agent" {
  count = var.create_bedrock_agent_role ? 1 : 0
  name  = "bedrock-agent-invoke-model"
  role  = aws_iam_role.bedrock_agent[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Cross-region inference profile: the agent invokes via the inference-
        # profile ARN, which routes to the underlying foundation model in one of
        # several regions. IAM must allow the profile ARN AND each regional
        # foundation-model ARN it can route to.
        Sid      = "InvokeModel"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = var.bedrock_model_arns
      }
    ]
  })
}
