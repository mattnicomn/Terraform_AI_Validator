locals {
  role_name = "${var.function_name}-exec"
}

# Package the single-file Lambda into a zip
data "archive_file" "zip" {
  type        = "zip"
  source_file = var.source_file
  output_path = "${path.module}/.build/${var.function_name}.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name               = local.role_name
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
  tags               = var.tags
}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# _Minimal_ inline policy for this function:
# - CloudWatch Logs
# - S3 read (source), write+tag (dest+results)
# - Comprehend PII
# NOTE: SNS publish is attached from ROOT (so we can reuse your sns_alerts module and avoid circular deps)
data "aws_iam_policy_document" "inline" {
  statement {
    sid     = "Logs"
    effect  = "Allow"
    actions = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }

  statement {
    sid     = "S3ReadSource"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::${var.source_bucket}/*"
    ]
  }

  statement {
    sid     = "S3WriteResultsAndDest"
    effect  = "Allow"
    actions = ["s3:PutObject","s3:PutObjectTagging","s3:GetObjectTagging"]
    resources = [
      "arn:aws:s3:::${var.destination_bucket}/*",
      "arn:aws:s3:::${var.results_bucket}/*"
    ]
  }

  statement {
    sid     = "ComprehendDetectPII"
    effect  = "Allow"
    actions = ["comprehend:DetectPiiEntities"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "inline" {
  name   = "${var.function_name}-inline"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.inline.json
}

# (Optional) CloudWatch log group with retention
resource "aws_cloudwatch_log_group" "lg" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  description   = var.description
  role          = aws_iam_role.lambda_exec.arn
  filename      = data.archive_file.zip.output_path
  handler       = "lambda_function.lambda_handler"
  runtime       = var.runtime
  timeout       = var.timeout
  memory_size   = var.memory_size
  architectures = [var.architecture]

  environment {
    variables = merge({
      SNS_TOPIC_ARN      = var.sns_topic_arn
      SOURCE_BUCKETS     = var.source_bucket
      DESTINATION_BUCKETS= var.destination_bucket
      RESULTS_BUCKET     = var.results_bucket
    }, var.extra_env)
  }

  depends_on = [aws_cloudwatch_log_group.lg]
  tags       = var.tags
}

# Allow Bedrock Agent to invoke this Lambda (matches your CFN intent)
resource "aws_lambda_permission" "bedrock_invoke" {
  statement_id  = "AllowBedrock"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "bedrock.amazonaws.com"
  # optional: limit by source account
  # source_account = data.aws_caller_identity.current.account_id
}
