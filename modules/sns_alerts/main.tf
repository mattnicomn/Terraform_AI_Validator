resource "aws_sns_topic" "this" {
  name              = var.topic_name
  kms_master_key_id = var.kms_key_id
  tags              = var.tags
}

# Create one email subscription per address (user must click the email to confirm)
resource "aws_sns_topic_subscription" "emails" {
  for_each = toset(var.email_endpoints)
  topic_arn = aws_sns_topic.this.arn
  protocol  = "email"
  endpoint  = each.key
}
