data "aws_iam_policy" "lambda_basic" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Processor role
resource "aws_iam_role" "processor" {
  count = var.create_processor_role ? 1 : 0
  name  = var.processor_role_name
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect="Allow", Principal={ Service="lambda.amazonaws.com" }, Action="sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "processor_basic" {
  count      = var.create_processor_role ? 1 : 0
  role       = aws_iam_role.processor[0].name
  policy_arn = data.aws_iam_policy.lambda_basic.arn
}

# Optional extra inline policies (SNS publish, S3 full access, logs, comprehend read-only) like CFN
resource "aws_iam_policy" "processor_inline_combined" {
  count = var.create_processor_role ? 1 : 0
  name  = "SecurityDataTransferProcessor-Policy"
  path  = "/service-role/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect="Allow", Action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource="*" },
      { Effect="Allow", Action=["sns:Publish"], Resource="arn:aws:sns:*:*:SecurityDataTransferAlerts" },
      { Effect="Allow", Action=["s3:*"], Resource="*" },
      { Effect="Allow", Action=["comprehend:DetectPiiEntities","comprehend:ContainsPiiEntities"], Resource="*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "processor_inline_attach" {
  count      = var.create_processor_role ? 1 : 0
  role       = aws_iam_role.processor[0].name
  policy_arn = aws_iam_policy.processor_inline_combined[0].arn
}

# Prompt role
resource "aws_iam_role" "prompt" {
  count = var.create_prompt_role ? 1 : 0
  name  = var.prompt_role_name
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect="Allow", Principal={ Service="lambda.amazonaws.com" }, Action="sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "prompt_basic" {
  count      = var.create_prompt_role ? 1 : 0
  role       = aws_iam_role.prompt[0].name
  policy_arn = data.aws_iam_policy.lambda_basic.arn
}

# Mirrors the CFN prompt role extras (Bedrock Invoke, S3 Get/Put, SSM GetParameter, kms/* (use sparingly))
resource "aws_iam_policy" "prompt_inline" {
  count = var.create_prompt_role && var.attach_extra_prompt_policies ? 1 : 0
  name  = "BedrockPromptHandler-Extras"
  path  = "/service-role/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect="Allow", Action=["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"], Resource="*" },
      { Effect="Allow", Action=["s3:GetObject","s3:GetObjectTagging","s3:PutObject"], Resource="*" },
      { Effect="Allow", Action=["ssm:GetParameter"], Resource="arn:aws:ssm:*:*:parameter/private_key.pem" },
      { Effect="Allow", Action=["kms:*","ssm:*"], Resource="*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "prompt_inline_attach" {
  count      = var.create_prompt_role && var.attach_extra_prompt_policies ? 1 : 0
  role       = aws_iam_role.prompt[0].name
  policy_arn = aws_iam_policy.prompt_inline[0].arn
}

# Role for Bedrock Agent (maps CFN IAMRoleBedRockSecurityDataTransferRole)
resource "aws_iam_role" "bedrock_agent" {
  name = "BedRockSecurityDataTransferRole"
  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect="Allow", Principal={ Service="bedrock.amazonaws.com" }, Action="sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_policy" "bedrock_agent_allow_invoke_lambda" {
  name  = "BedrockAgent_LambdaInvoke"
  path  = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect="Allow",
      Action=["lambda:InvokeFunction"],
      Resource=["arn:aws:lambda:*:*:function:SecurityDataTransferProcessor"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_agent_attach_admins" {
  role       = aws_iam_role.bedrock_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # mirrors CFN (consider least privilege!)
}

resource "aws_iam_role_policy_attachment" "bedrock_agent_attach_invoke" {
  role       = aws_iam_role.bedrock_agent.name
  policy_arn = aws_iam_policy.bedrock_agent_allow_invoke_lambda.arn
}
