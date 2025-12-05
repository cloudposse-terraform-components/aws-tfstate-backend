# Remote state lookup for the account-map component (or fallback to static mapping).
#
# When account_map_enabled is true:
#   - Performs remote state lookup to retrieve account mappings from the account-map component
#   - Uses account_map_environment, account_map_stage, account_map_tenant for the lookup
#
# When account_map_enabled is false:
#   - Bypasses the remote state lookup (bypass = true)
#   - Returns the static account_map variable as defaults instead
#   - Allows the component to function without the account-map dependency
module "account_map" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "1.8.0"

  component   = "account-map"
  tenant      = var.account_map_enabled ? (var.account_map_tenant != null ? var.account_map_tenant : module.this.tenant) : null
  environment = var.account_map_enabled ? var.account_map_environment : null
  stage       = var.account_map_enabled ? var.account_map_stage : null

  context = module.this.context

  # When account_map is disabled, bypass remote state and use the static account_map variable
  bypass   = !var.account_map_enabled
  defaults = var.account_map
}
