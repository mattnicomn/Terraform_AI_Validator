variable "application_domain" {
  description = "Application domain (e.g. ai.usmissionhero.com) served by this frontend."
  type        = string
}

variable "bucket_name" {
  description = "Private S3 bucket name for frontend hosting (account-scoped)."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone id for the DELEGATED ai.usmissionhero.com zone (account 102). Used for ACM DNS validation + alias record."
  type        = string
}

variable "default_root_object" {
  description = "CloudFront default root object."
  type        = string
  default     = "index.html"
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "enable_frontend_delivery" {
  description = "Stage gate. false = Stage 1 (create bucket/security/OAC/ACM cert + validation record only); true = Stage 2 (also create ACM validation wait, CloudFront distribution, bucket policy, and application alias). Set true only after the delegated zone resolves publicly."
  type        = bool
}
