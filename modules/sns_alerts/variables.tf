variable "topic_name" {
  description = "SNS topic name"
  type        = string
  default     = "SecurityDataTransferAlerts"
}

variable "email_endpoints" {
  description = "List of email subscribers"
  type        = list(string)
  default     = []
}

variable "kms_key_id" {
  description = "Optional KMS key for SNS server-side encryption"
  type        = string
  default     = null
}

variable "tags" {
  type        = map(string)
  default     = {}
}
