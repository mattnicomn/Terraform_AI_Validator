# Variables for US Mission Hero Terraform Configuration

variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "project" {
  type        = string
  description = "Project name"
  default     = "US Mission Hero"
}

variable "environment" {
  type        = string
  description = "Environment (dev, staging, prod)"
  default     = "prod"
}

variable "owner" {
  type        = string
  description = "Owner/team name"
  default     = "Platform Team"
}

variable "bucket_name" {
  type        = string
  description = "S3 bucket name for frontend"
  default     = "bedrockfrontend"
}

variable "cloudfront_distribution_id" {
  type        = string
  description = "Existing CloudFront distribution ID"
  default     = "EOK4YOONDZGMT"
}

variable "allow_destroy" {
  type        = bool
  description = "Allow bucket to be destroyed (set to false for production)"
  default     = false
}

variable "enable_versioning" {
  type        = bool
  description = "Enable S3 bucket versioning"
  default     = false
}
