variable "function_name"    { type = string }
variable "role_arn"         { type = string }
variable "runtime"          { type = string }
variable "handler"          { type = string }
variable "timeout"          { type = number default = 60 }
variable "memory_size"      { type = number default = 256 }
variable "architectures"    { type = list(string) default = ["x86_64"] }
variable "log_group_name"   { type = string }
variable "package_type"     { type = string default = "Zip" } # or "Image"
variable "image_uri"        { type = string default = null }

variable "code_s3_bucket"   { type = string default = null }
variable "code_s3_key"      { type = string default = null }
variable "code_s3_version"  { type = string default = null }
variable "code_kms_key_arn" { type = string default = null }

variable "tags" { type = map(string) default = {} }
