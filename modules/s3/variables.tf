variable "buckets" {
  description = <<EOT
Map of bucket configs. Keys are logical names you choose (e.g., "source", "destination", "results").
Each value:
  - name        (string, required)   : the actual bucket name
  - ownership   (string, optional)   : "BucketOwnerEnforced" | "BucketOwnerPreferred"
  - versioning  (bool,   optional)   : enable versioning
  - force_destroy (bool, optional)   : allow TF to delete non-empty buckets
  - tags        (map(string), optional)
EOT
  type = map(object({
    name          = string
    ownership     = optional(string, "BucketOwnerEnforced")
    versioning    = optional(bool, false)
    force_destroy = optional(bool, false)
    tags          = optional(map(string), {})
  }))
}

# Tell the module which map keys correspond to the three functional buckets
variable "source_key" {
  type        = string
  description = "Key in var.buckets for the SOURCE bucket"
}
variable "destination_key" {
  type        = string
  description = "Key in var.buckets for the DESTINATION bucket"
}
variable "results_key" {
  type        = string
  description = "Key in var.buckets for the RESULTS bucket"
}

# Optional principals (role/user ARNs) for bucket policies
variable "source_read_principals" {
  type        = list(string)
  default     = []
  description = "Principals allowed to GetObject from the SOURCE bucket (e.g., Lambda role ARN)"
}
variable "dest_write_principals" {
  type        = list(string)
  default     = []
  description = "Principals allowed to PutObject/Tag in the DESTINATION bucket"
}
variable "results_write_principals" {
  type        = list(string)
  default     = []
  description = "Principals allowed to PutObject/Tag in the RESULTS bucket"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Common tags applied to all buckets"
}
