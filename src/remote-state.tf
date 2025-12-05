# Remote state lookup for the account-map component (or fallback to static mapping).
#
# When account_map_enabled is true and module.this.enabled is true:
#   - Performs remote state lookup to retrieve account mappings from the account-map component
#   - Uses account_map_environment, account_map_stage, account_map_tenant for the lookup
#   - If these variables are null, uses the current context (module.this) values
#
# When account_map_enabled is false OR module.this.enabled is false:
#   - Bypasses the remote state lookup (bypass = true)
#   - Returns the static account_map variable as defaults instead
#   - Allows the component to function without the account-map dependency
module "account_map" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "1.8.0"

  component   = "account-map"
  tenant      = local.account_map_lookup_enabled ? (var.account_map_tenant != null ? var.account_map_tenant : module.this.tenant) : null
  environment = local.account_map_lookup_enabled ? (var.account_map_environment != null ? var.account_map_environment : module.this.environment) : null
  stage       = local.account_map_lookup_enabled ? (var.account_map_stage != null ? var.account_map_stage : module.this.stage) : null

  context = module.this.context

  # When account_map is disabled or the component is disabled, bypass remote state
  bypass   = !local.account_map_lookup_enabled
  defaults = var.account_map
}

locals {
  # Only perform account-map lookup when both account_map_enabled and component enabled
  account_map_lookup_enabled = var.account_map_enabled && module.this.enabled
}
