variable "s3_bucket_domain"  { type = string }
variable "oac_name"          { type = string }
variable "default_origin_id" { type = string }
variable "aliases"           { type = list(string) default = [] }

variable "cache_policy_names"          { type = list(string) default = ["Managed-CachingDisabled"] }
variable "origin_request_policy_names" { type = list(string) default = ["Managed-AllViewerExceptHostHeader"] }
variable "response_headers_policy_id"  { type = string default = "" }

# Optional: create S3 bucket policy allowing CloudFront to GetObject
variable "create_s3_policy" { type = bool default = false }
variable "s3_bucket_arn"    { type = string default = null }
variable "distribution_arn" { type = string default = null }

variable "tags" { type = map(string) default = {} }
