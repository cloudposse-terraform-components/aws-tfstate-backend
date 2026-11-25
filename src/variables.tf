variable "region" {
  type        = string
  description = "AWS Region"
}

variable "force_destroy" {
  type        = bool
  description = "A boolean that indicates the terraform state S3 bucket can be destroyed even if it contains objects. These objects are not recoverable."
  default     = false
}

variable "prevent_unencrypted_uploads" {
  type        = bool
  description = "Prevent uploads of unencrypted objects to S3"
  default     = true
}

variable "enable_point_in_time_recovery" {
  type        = bool
  description = "Enable DynamoDB point-in-time recovery"
  default     = true
}

variable "access_roles" {
  description = <<-EOT
    Map of access roles to create (key is role name, use "default" for same as component).

    For `allowed_roles` and `denied_roles`, the map keys can be either AWS account IDs (12-digit numbers) or account names.
    If account names are used, they will be resolved to account IDs using the `account_map` variable.
    The values are lists of role names (e.g., ["admin", "terraform"]). Use ["*"] to allow/deny all roles in an account.

    For `allowed_permission_sets` and `denied_permission_sets`, the map keys can be either AWS account IDs or account names.
    If account names are used, they will be resolved to account IDs using the `account_map` variable.
    The values are lists of permission set names (e.g., ["TerraformUpdateAccess"]).

    Role ARNs are constructed as: `arn:{partition}:iam::{account_id}:role/{namespace}-{environment}-{stage}-{name}-{role_name}`
    Permission set ARNs are constructed as: `arn:{partition}:iam::{account_id}:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_{permission_set_name}_*`
  EOT
  type = map(object({
    write_enabled           = bool
    allowed_roles           = map(list(string))
    denied_roles            = map(list(string))
    allowed_principal_arns  = list(string)
    denied_principal_arns   = list(string)
    allowed_permission_sets = map(list(string))
    denied_permission_sets  = map(list(string))
  }))
  default = {}
}

variable "access_roles_enabled" {
  type        = bool
  description = <<-EOT
    Enable access roles to be assumed. Set `false` for cold start to use a basic trust policy
    that only allows the current caller and explicitly allowed principals.
    Note that the current caller and any `allowed_principal_arns` will always be allowed to assume the role.
    EOT
  default     = true
}

variable "dynamodb_enabled" {
  type        = bool
  default     = true
  description = "Whether to create the DynamoDB table."
}

variable "s3_state_lock_enabled" {
  type        = bool
  default     = false
  description = "Whether to use S3 for state lock. If true, the DynamoDB table will not be created."
}


variable "use_organization_id" {
  type        = bool
  description = <<-EOT
    If `true`, use AWS Organization ID (`aws:PrincipalOrgID` condition) in trust policies instead of
    listing individual account root ARNs. When enabled, the principal is set to `*` and access is
    restricted to the AWS Organization via a condition.

    This is recommended (and often required) when you have many accounts because IAM trust policies
    have a maximum size limit of 4096 characters. Listing each account root ARN individually can
    easily exceed this limit in organizations with more than ~30 accounts.

    If `false`, each account root is listed individually in the principals block, which may hit
    the trust policy size limit in larger organizations.
  EOT
  default     = false
}

variable "sse_encryption" {
  type        = string
  default     = "AES256"
  description = <<-EOT
    The server-side encryption algorithm for the state bucket.
    Valid values are `AES256`, `aws:kms`, and `aws:kms:dsse`.
    EOT
}

variable "kms_master_key_id" {
  type        = string
  default     = null
  description = <<-EOT
    AWS KMS key ID or ARN for SSE-KMS encryption of the state bucket.
    Used only when `sse_encryption` is `aws:kms` or `aws:kms:dsse`; `null` uses the AWS managed `aws/s3` key.
    EOT
}

variable "logging" {
  type = object({
    target_bucket = string
    target_prefix = string
  })
  default     = null
  description = <<-EOT
    S3 server access logging for the state bucket: the target bucket (same account and Region) and key prefix.
    `null` disables access logging.
    EOT
}

variable "s3_replication_enabled" {
  type        = bool
  default     = false
  description = "Replicate the state bucket to `s3_replica_bucket_arn`. The replica bucket must exist and have versioning enabled."
}

variable "s3_replica_bucket_arn" {
  type        = string
  default     = ""
  description = "ARN of the replica (destination) bucket. Required when `s3_replication_enabled` is `true`."

  validation {
    condition     = !var.s3_replication_enabled || var.s3_replica_bucket_arn != ""
    error_message = "`s3_replica_bucket_arn` is required when `s3_replication_enabled` is `true`."
  }
}

variable "s3_replica_kms_key_arn" {
  type        = string
  default     = null
  description = <<-EOT
    ARN of a customer managed KMS key in the replica Region that encrypts the replicas.
    Required to replicate SSE-KMS state (`sse_encryption = "aws:kms"`): S3 skips SSE-KMS objects
    unless the rule names a replica key. `null` (default) replicates unencrypted and SSE-S3 objects only.
    EOT
}

variable "s3_replication_delete_marker_enabled" {
  type        = bool
  default     = true
  description = "Replicate delete markers to the replica bucket. Set to `false` to keep the replica as an independent copy: deleting a state object in the source then leaves it visible in the replica."
}

variable "lifecycle_enabled" {
  type        = bool
  default     = false
  description = <<-EOT
    Create a lifecycle configuration on the state bucket. It never expires current objects: it removes
    noncurrent state versions (keeping the newest `noncurrent_versions_to_keep`), expired delete markers,
    and multipart uploads left incomplete for 7 days.
    EOT
}

variable "noncurrent_version_expiration_days" {
  type        = number
  default     = 90
  description = <<-EOT
    Days after a state version becomes noncurrent before it is deleted.
    With `s3_state_lock_enabled` the bucket has a 7-day GOVERNANCE Object Lock retention, so this must exceed 7.
    EOT

  validation {
    condition     = var.noncurrent_version_expiration_days >= 1
    error_message = "`noncurrent_version_expiration_days` must be at least 1."
  }
}

variable "noncurrent_versions_to_keep" {
  type        = number
  default     = 10
  description = "Newest noncurrent versions of each state object kept regardless of age (1-100)."

  validation {
    condition     = var.noncurrent_versions_to_keep >= 1 && var.noncurrent_versions_to_keep <= 100
    error_message = "`noncurrent_versions_to_keep` must be between 1 and 100."
  }
}
