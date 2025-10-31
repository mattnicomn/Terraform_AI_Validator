variable "name" { type = string }

# Allow different Lambdas per route
variable "routes" {
  description = <<EOT
List of routes to create. Each object:
{
  method            = "GET" | "POST" | ...
  path              = "/scan-file"
  target_lambda_arn = "arn:aws:lambda:..."
}
EOT
  type = list(object({
    method            = string
    path              = string
    target_lambda_arn = string
  }))
}

# CORS
variable "cors_allow_origins" { type = list(string)  default = ["*"] }
variable "cors_allow_headers" { type = list(string)  default = ["authorization","content-type"] }
variable "cors_allow_methods" { type = list(string)  default = ["OPTIONS","GET","POST","PUT","PATCH","DELETE"] }

# Stage
variable "auto_deploy" { type = bool default = true }

# API flags/tags
variable "disable_execute_api_endpoint" { type = bool default = false }
variable "tags" { type = map(string) default = {} }

# Optional JWT authorizer (Cognito)
variable "jwt_authorizer" {
  description = "Set to null to disable. If provided, creates a JWT authorizer."
  type = object({
    issuer   = string
    audience = list(string)
  })
  default = null
}

# Which routes require JWT (match on 'METHOD /path', e.g., 'POST /scan-bucket')
variable "protected_routes" {
  type        = list(string)
  default     = []
  description = "Route keys to protect with JWT authorizer."
}
