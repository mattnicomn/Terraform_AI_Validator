output "processor_role_arn"  { value = try(aws_iam_role.processor[0].arn, null) }
output "processor_role_name" { value = try(aws_iam_role.processor[0].name, null) }
output "prompt_role_arn"     { value = try(aws_iam_role.prompt[0].arn, null) }
output "prompt_role_name"    { value = try(aws_iam_role.prompt[0].name, null) }
output "bedrock_agent_role_arn" { value = aws_iam_role.bedrock_agent.arn }
