provider "aws" {
  region = var.region
}

variable "account_map_enabled" {
  type        = bool
  description = <<-EOT
    Enable account map lookups for resolving account names to account IDs.
    When `true`, uses the `account_map` variable to resolve account names.
    When `false`, account IDs must be provided directly in `access_roles`.
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
