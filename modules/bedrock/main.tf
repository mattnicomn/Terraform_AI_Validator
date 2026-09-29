# =============================================================================
# AI Validator Bedrock module (destination account 102).
# Requires AWS provider with Bedrock Agent GA (>= 5.56+).
#
# UNRESOLVED (Phase 0.6): the authoritative full agent INSTRUCTION was not
# recovered from the live source. var.instruction is a placeholder until then;
# do not treat the agent as deployment-ready.
#
# prepare_agent + aliases depend on MODEL ACCESS being enabled in 102 (a later
# AWS gate). They are guarded by var.prepare_agent (default false) so a first
# apply does not fail on an unavailable/ungranted model.
# =============================================================================

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = var.agent_name
  description                 = var.description
  foundation_model            = var.foundation_model
  idle_session_ttl_in_seconds = 600
  instruction                 = var.instruction
  agent_resource_role_arn     = var.agent_resource_role_arn
  prepare_agent               = var.prepare_agent # gated on model access (later)
  tags                        = var.tags

  dynamic "guardrail_configuration" {
    for_each = var.guardrail_identifier != null ? [1] : []
    content {
      guardrail_identifier = var.guardrail_identifier
      guardrail_version    = var.guardrail_version
    }
  }
}

# Action group: the core executor relationship (agent -> Processor Lambda).
resource "aws_bedrockagent_agent_action_group" "this" {
  agent_id           = aws_bedrockagent_agent.this.id
  agent_version      = "DRAFT"
  action_group_name  = var.action_group_name
  action_group_state = "ENABLED"
  # Do NOT trigger PrepareAgent from the action group. The provider default for
  # this argument is true, which would prepare the DRAFT agent on create/update;
  # gate it on var.prepare_agent (default false) so no preparation occurs until
  # model-access entitlement is separately proven (later gate).
  prepare_agent = var.prepare_agent

  api_schema {
    payload = var.openapi_payload
  }

  action_group_executor {
    lambda = var.action_group_lambda
  }
}

# Aliases only make sense after the agent is prepared (a prepared version exists).
resource "aws_bedrockagent_agent_alias" "aliases" {
  for_each         = var.prepare_agent ? { for a in var.aliases : a.name => a } : {}
  agent_id         = aws_bedrockagent_agent.this.id
  agent_alias_name = each.value.name
  tags             = var.tags
}

output "agent_id" { value = aws_bedrockagent_agent.this.id }

# Alias id of the first created alias (only when prepare_agent = true). Null
# until the agent is prepared and an alias exists (gated on model access).
output "agent_alias_id" {
  value = length(aws_bedrockagent_agent_alias.aliases) > 0 ? values(aws_bedrockagent_agent_alias.aliases)[0].agent_alias_id : null
}
