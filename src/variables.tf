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
    If `true`, use AWS Organization ID in trust policy principals instead of listing individual account roots.
    This significantly reduces the trust policy size and is recommended when you have many accounts.
    If `false`, list each account root individually in the principals list.
  EOT
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map           = map(string)
    audit_account_account_name = optional(string, "")
    root_account_account_name  = optional(string, "")
  })
  description = <<-EOT
    Static account map for resolving account names to account IDs.
    Used by `access_roles` when account names are specified instead of account IDs.
    This replaces the account-map component dependency.
    EOT
  default = {
    full_account_map           = {}
    audit_account_account_name = ""
    root_account_account_name  = ""
  }
}
