provider "aws" {
  region = var.region
}

variable "account_map_enabled" {
  type        = bool
  description = <<-EOT
    When true, uses the account-map component to look up account IDs dynamically.
    When false, uses the static account_map variable instead. Set to false when
    using static account mappings without the account-map component.
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
    Static account map used when account_map_enabled is false.
    Provides account name to account ID mapping without requiring the account-map component.
  EOT
  default = {
    full_account_map           = {}
    audit_account_account_name = ""
    root_account_account_name  = ""
  }
}

variable "account_map_environment" {
  type        = string
  description = "The environment where the account-map component is deployed (for remote state lookup). Leave null to use the current environment."
  default     = null
}

variable "account_map_stage" {
  type        = string
  description = "The stage where the account-map component is deployed (for remote state lookup). Leave null to use the current stage."
  default     = null
}

variable "account_map_tenant" {
  type        = string
  description = "The tenant where the account-map component is deployed (for remote state lookup). Leave empty to use the current tenant."
  default     = null
}
