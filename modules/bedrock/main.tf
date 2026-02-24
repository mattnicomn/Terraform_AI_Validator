# These resources require AWS provider that supports bedrock agent GA (>= 5.56+).
# Names may vary slightly depending on provider version.

resource "aws_bedrockagent_agent" "this" {
  agent_name                      = var.agent_name
  description                     = var.description
  foundation_model                = var.foundation_model
  idle_session_ttl_in_seconds     = 600
  instruction                     = var.instruction
  agent_resource_role_arn         = var.agent_resource_role_arn
  prepare_agent                   = true
  tags                            = var.tags

  # Guardrail configuration for enhanced security
  dynamic "guardrail_configuration" {
    for_each = var.guardrail_identifier != null ? [1] : []
    content {
      guardrail_identifier = var.guardrail_identifier
      guardrail_version    = var.guardrail_version
    }
  }

  # Prompt override configuration for better control
  dynamic "prompt_override_configuration" {
    for_each = var.enable_prompt_override ? [1] : []
    content {
      prompt_configurations {
        prompt_type     = "PRE_PROCESSING"
        prompt_state    = "ENABLED"
        inference_configuration {
          temperature   = 0.0
          top_p         = 0.9
          top_k         = 250
          max_length    = 2048
          stop_sequences = []
        }
      }
    }
  }
}

resource "aws_bedrockagent_action_group" "this" {
  agent_id          = aws_bedrockagent_agent.this.id
  action_group_name = var.action_group_name
  action_group_state = "ENABLED"

  api_schema {
    payload = var.openapi_payload
  }

  action_group_executor {
    lambda {
      lambda_arn = var.action_group_lambda
    }
  }
}

resource "aws_bedrockagent_agent_alias" "aliases" {
  for_each      = { for a in var.aliases : a.name => a }
  agent_id      = aws_bedrockagent_agent.this.id
  agent_alias_name = each.value.name
  routing_configuration {
    agent_version = each.value.version
  }
  tags = var.tags
}

output "agent_id" { value = aws_bedrockagent_agent.this.id }
