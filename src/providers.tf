variable "account_map_enabled" {
  type        = bool
  description = <<-EOT
    When true, uses the account-map component to look up account IDs dynamically.
    When false, uses the static account_map variable instead. Set to false when
    deploying without the account-map component or when using static account mappings.
    EOT
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map              = map(string)
    iam_role_arn_templates        = optional(map(string), {})
    identity_account_account_name = optional(string, "identity")
  })
  description = <<-EOT
    Static account map used when account_map_enabled is false.
    Provides account name to account ID mapping without requiring the account-map component.

    - full_account_map: Map of account name to account ID
    - iam_role_arn_templates: Optional map of account name to IAM role ARN template
      (e.g., { "identity" = "arn:aws:iam::123456789012:role/acme-gbl-identity-%s" })
    - identity_account_account_name: Name of the identity account (default: "identity")
    EOT
  default = {
    full_account_map              = {}
    iam_role_arn_templates        = {}
    identity_account_account_name = "identity"
  }
}

provider "aws" {
  region = var.region
}
