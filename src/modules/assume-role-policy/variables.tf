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
  default     = false
}

variable "account_map" {
  type = object({
    full_account_map              = map(string)
    iam_role_arn_templates        = optional(map(string), {})
    identity_account_account_name = optional(string, "identity")
  })
  description = <<-EOT
    Account map for resolving account names to account IDs and IAM role ARN templates.
    Required when using account names (non-numeric keys) in allowed_roles, denied_roles, allowed_permission_sets, or denied_permission_sets.

    - full_account_map: Map of account name to account ID
    - iam_role_arn_templates: Map of account name to IAM role ARN template with single %s placeholder for role name
      (e.g., { "identity" = "arn:aws:iam::123456789012:role/acme-core-gbl-identity-%s" })
    - identity_account_account_name: Name of the identity account (default: "identity")
  EOT
  default = {
    full_account_map              = {}
    iam_role_arn_templates        = {}
    identity_account_account_name = "identity"
  }
}

variable "team_permission_sets_enabled" {
  type        = bool
  description = <<-EOT
    When true, any roles in the identity account referenced in `allowed_roles` will cause
    corresponding AWS SSO PermissionSets to be automatically included in the trust policy.
    This converts role names like "developers" to permission sets like "IdentityDevelopersTeamAccess".
  EOT
  default     = true
}

variable "team_permission_set_name_pattern" {
  type        = string
  description = <<-EOT
    The pattern used to generate the AWS SSO PermissionSet name for each team.
    Uses Go template syntax with a single %s placeholder for the team name (title-cased).
    Example: "Identity%sTeamAccess" converts "developers" to "IdentityDevelopersTeamAccess"
  EOT
  default     = "Identity%sTeamAccess"
}

variable "iam_role_arn_template" {
  type        = string
  description = <<-EOT
    Fallback template for constructing IAM role names when no per-account template exists.
    Should be a format string with two %s placeholders: first for account name, second for role name.
    Example: "acme-gbl-%s-%s" would produce role names like "acme-gbl-identity-admin"

    Note: Per-account templates from account_map.iam_role_arn_templates take precedence.
    Those templates use a single %s placeholder for just the role name.

    If null and no per-account template exists, role names are used as-is.
  EOT
  default     = null
}
