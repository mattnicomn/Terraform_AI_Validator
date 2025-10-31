variable "function_name"       { type = string }
variable "description"         { type = string  default = "" }
variable "timeout"             { type = number  default = 60 }
variable "memory_size"         { type = number  default = 512 }
variable "runtime"             { type = string  default = "python3.11" }
variable "architecture"        { type = string  default = "x86_64" } # or arm64

# Where your code file lives in the repo
variable "source_file"         { type = string  } # e.g. "${path.root}/lambda/SecurityDataTransferProcessor/lambda_function.py"

# Env values to inject (match your Python)
variable "sns_topic_arn"       { type = string }
variable "source_bucket"       { type = string }
variable "destination_bucket"  { type = string }
variable "results_bucket"      { type = string }

# Optional extra env vars
variable "extra_env" {
  type    = map(string)
  default = {}
}

# Tags
variable "tags" {
  type    = map(string)
  default = {}
}
