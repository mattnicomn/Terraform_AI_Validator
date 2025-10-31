output "function_arn" { value = aws_lambda_function.this.arn }
output "role_arn"     { value = aws_iam_role.lambda_exec.arn }
output "role_name"    { value = aws_iam_role.lambda_exec.name }
