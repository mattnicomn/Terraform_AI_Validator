output "processor_role_arn" { value = try(aws_iam_role.processor[0].arn, null) }
output "prompt_role_arn"    { value = try(aws_iam_role.prompt[0].arn, null) }
output "bedrock_agent_role_arn" { value = aws_iam_role.bedrock_agent.arn }
