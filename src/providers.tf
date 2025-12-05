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
    full_account_map = map(string)
  })
  description = <<-EOT
    Static account map used when account_map_enabled is false.
    Provides account name to account ID mapping without requiring the account-map component.
    EOT
  default = {
    full_account_map = {}
  }
}

variable "account_map_component_name" {
  type        = string
  description = "The name of the account-map component"
  default     = "account-map"
}

variable "account_map_tenant" {
  type        = string
  description = "The tenant where the account-map component is deployed (defaults to current tenant)"
  default     = "core"
}

variable "account_map_environment" {
  type        = string
  description = "The environment where the account-map component is deployed (e.g., 'gbl')"
  default     = "gbl"
}

variable "account_map_stage" {
  type        = string
  description = "The stage where the account-map component is deployed (e.g., 'root')"
  default     = "root"
}

provider "aws" {
  region = var.region
}
