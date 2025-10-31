data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  normalized = [
    for r in var.routes : {
      method            = upper(r.method)
      path              = r.path
      path_part         = replace(r.path, "^/", "")
      key               = "${upper(r.method)} ${r.path}"
      target_lambda_arn = r.target_lambda_arn
    }
  ]
  routes_by_key = { for r in local.normalized : r.key => r }
}

resource "aws_apigatewayv2_api" "this" {
  name                         = var.name
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = var.disable_execute_api_endpoint

  cors_configuration {
    allow_headers     = var.cors_allow_headers
    allow_methods     = var.cors_allow_methods
    allow_origins     = var.cors_allow_origins
    max_age           = 3600
    allow_credentials = false
  }

  tags = var.tags
}

# Optional JWT authorizer (Cognito)
resource "aws_apigatewayv2_authorizer" "jwt" {
  count = var.jwt_authorizer == null ? 0 : 1

  api_id           = aws_apigatewayv2_api.this.id
  authorizer_type  = "JWT"
  name             = "jwt"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    issuer   = var.jwt_authorizer.issuer
    audience = var.jwt_authorizer.audience
  }
}

# One integration per route (since Lambda ARNs can differ)
resource "aws_apigatewayv2_integration" "lambda" {
  for_each = local.routes_by_key

  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
  integration_uri        = each.value.target_lambda_arn
}

# Routes (attach JWT on protected ones)
resource "aws_apigatewayv2_route" "this" {
  for_each = local.routes_by_key

  api_id    = aws_apigatewayv2_api.this.id
  route_key = each.value.key
  target    = "integrations/${aws_apigatewayv2_integration.lambda[each.key].id}"

  authorization_type = contains(var.protected_routes, each.value.key) && (var.jwt_authorizer != null) ? "JWT" : null
  authorizer_id      = contains(var.protected_routes, each.value.key) && (var.jwt_authorizer != null) ? aws_apigatewayv2_authorizer.jwt[0].id : null
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = var.auto_deploy
}

# Per-route Lambda permission (least privilege)
locals {
  route_invoke_arns = {
    for k, r in local.routes_by_key :
    k => "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.this.id}/*/${r.method}/${r.path_part}"
  }
}

resource "aws_lambda_permission" "invoke_by_apigw" {
  for_each = local.routes_by_key

  statement_id  = "AllowInvokeByApiGateway-${replace(each.key, "/[^A-Za-z0-9]/", "-")}"
  action        = "lambda:InvokeFunction"
  function_name = each.value.target_lambda_arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = local.route_invoke_arns[each.key]
}
