# =============================================================================
# AI Validator — NEW DNS module (account 102 side of subdomain delegation)
# Owns ONLY the delegated hosted zone for ai.usmissionhero.com and records
# INSIDE it. MUST NOT manage the parent usmissionhero.com zone or the parent
# NS delegation record (that is owned by website_infrastructure, account 253,
# via a separate future gate).
# Phase 2 refactor — NOT YET APPLIED.
# =============================================================================

resource "aws_route53_zone" "ai" {
  name    = var.application_domain # ai.usmissionhero.com
  comment = "Delegated subdomain zone for AI Validator (account-owned). Parent NS delegation lives in website_infrastructure."
  tags    = var.tags
}

variable "application_domain" {
  description = "Delegated subdomain (e.g. ai.usmissionhero.com)."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

output "zone_id" {
  value = aws_route53_zone.ai.zone_id
}

output "name_servers" {
  description = "NS records for the delegated zone. Hand these to website_infrastructure to create the parent NS delegation record in the usmissionhero.com zone."
  value       = aws_route53_zone.ai.name_servers
}
