variable "allowed_roles" {
  type        = map(list(string))
  description = <<-EOT
    Map of account:[role, role...] specifying roles allowed to assume the role.
    Account keys can be AWS account IDs (12-digit numbers) or account names that will be resolved via account_map.
    Role names are used to construct ARNs using iam_role_arn_template. Use `*` as role for entire account.
  EOT
  default     = {}
}

variable "denied_roles" {
  type        = map(list(string))
  description = <<-EOT
    Map of account:[role, role...] specifying roles explicitly denied permission to assume the role.
    Account keys can be AWS account IDs (12-digit numbers) or account names that will be resolved via account_map.
    Role names are used to construct ARNs using iam_role_arn_template. Use `*` as role for entire account.
  EOT
  default     = {}
}

variable "allowed_principal_arns" {
  type        = list(string)
  description = "List of AWS principal ARNs allowed to assume the role."
  default     = []
}

variable "denied_principal_arns" {
  type        = list(string)
  description = "List of AWS principal ARNs explicitly denied access to the role."
  default     = []
}

variable "allowed_permission_sets" {
  type        = map(list(string))
  description = <<-EOT
    Map of account:[PermissionSet, PermissionSet...] specifying AWS SSO PermissionSets allowed to assume the role.
    Account keys can be AWS account IDs (12-digit numbers) or account names that will be resolved via account_map.
  EOT
  default     = {}
}

variable "denied_permission_sets" {
  type        = map(list(string))
  description = <<-EOT
    Map of account:[PermissionSet, PermissionSet...] specifying AWS SSO PermissionSets denied access to the role.
    Account keys can be AWS account IDs (12-digit numbers) or account names that will be resolved via account_map.
  EOT
  default     = {}
}

variable "iam_users_enabled" {
  type        = bool
  description = "If true, allow IAM users (not just assumed roles) to assume the role."
  default     = false
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
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map = map(string)
  })
  description = <<-EOT
    Static account map for resolving account names to account IDs.
    Required when using account names (non-numeric keys) in allowed_roles, denied_roles, allowed_permission_sets, or denied_permission_sets.
  EOT
  default = {
    full_account_map = {}
  }
}

variable "iam_role_arn_templates" {
  type        = map(string)
  description = <<-EOT
    Map of account name/ID to IAM role name template for that account.
    Each template should be a format string with a single %s placeholder for the role name.
    Example: { "identity" = "acme-gbl-identity-%s", "dev" = "acme-gbl-dev-%s" }

    This allows different accounts to have different role naming conventions.
    When an account is not found in this map, the role name is used as-is.
  EOT
  default     = {}
}
