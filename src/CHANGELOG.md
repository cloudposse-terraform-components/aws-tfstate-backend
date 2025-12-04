# Changelog

### Summary

This release removes the dependency on the `account-map` component's remote state. The `tfstate-backend` component now generates IAM assume role policies internally, enabling it to be deployed earlier in the bootstrap process before `account-map` is available.

This change is backwards compatible. Existing deployments should continue to work without modification.

### New Features

- **Removed `account-map` remote state dependency**: The component no longer requires the `account-map` component to be deployed or queries its remote state. The assume role policy logic has been internalized.

- **Static account map support**: Added `account_map` variable to provide account name-to-ID mappings directly. Account names in `allowed_roles`, `denied_roles`, `allowed_permission_sets`, and `denied_permission_sets` can be resolved using this static map.

- **`account_map_enabled` variable**: Controls whether account name resolution is enabled. When `false`, only numeric AWS account IDs can be used in role/permission set configurations.

- **Permission set support in access roles**: Added `allowed_permission_sets` and `denied_permission_sets` to `access_roles` configuration, enabling AWS SSO permission sets to be granted or denied access to the Terraform state backend roles.

- **Organization ID trust policy optimization**: Added `use_organization_id` variable (default: `true`) to use `aws:PrincipalOrgID` condition in trust policies instead of listing individual account root ARNs. This addresses the IAM trust policy size limit (4096 characters) which can be exceeded in organizations with many accounts.

- **Extracted `assume-role-policy` submodule**: Created a reusable submodule at `modules/assume-role-policy` that generates IAM trust policy documents independently without remote state dependencies.

### Notes

- If using account names (not account IDs) in `access_roles`, you must provide the `account_map` variable with your account mappings
- The `use_organization_id` variable defaults to `true`, which is recommended for most deployments to avoid trust policy size limits
