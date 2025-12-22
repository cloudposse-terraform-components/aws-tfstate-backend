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

# Remote state lookup for the account-map component (or fallback to static mapping).
#
# When account_map_enabled is true:
#   - Performs remote state lookup to retrieve account mappings from the account-map component
#   - Uses account_map_tenant, account_map_environment, account_map_stage for the lookup
#
# When account_map_enabled is false:
#   - Bypasses the remote state lookup (bypass = true)
#   - Returns the static account_map variable as defaults instead
#   - Allows the component to function without the account-map dependency
module "account_map" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "1.8.0"

  component   = var.account_map_component_name
  tenant      = var.account_map_tenant
  environment = var.account_map_environment
  stage       = var.account_map_stage

  context = module.this.context

  # When account_map is disabled, bypass remote state and use the static account_map variable
  bypass   = !var.account_map_enabled
  defaults = var.account_map
}
