# Changelog

## Remove `account-map` dependency ([#54](https://github.com/cloudposse-terraform-components/aws-tfstate-backend/pull/54))

### Summary

This release removes the dependency on the `account-map` component as part of a larger effort to deprecate `account-map`. Previously, this component was tightly coupled with `account-map` because it used the `team-assume-role-policy` submodule from `account-map` to generate IAM trust policies. This change internalizes that functionality directly into the `tfstate-backend` component, eliminating the dependency.

This change is backwards compatible. Existing deployments should continue to work without modification.

### New Features

- **Removed `account-map` dependency**: The component no longer uses the `account-map` submodule for generating assume role policies. All trust policy logic has been moved into a new internal `assume-role-policy` submodule at `modules/assume-role-policy`.

- **Static account map support**: Added `account_map` variable to provide account name-to-ID mappings directly. Account names in `allowed_roles`, `denied_roles`, `allowed_permission_sets`, and `denied_permission_sets` can be resolved using this static map.

- **`account_map_enabled` variable**: Controls whether account name resolution is enabled. When `false`, only numeric AWS account IDs can be used in role/permission set configurations.

- **Permission set support in access roles**: Added `allowed_permission_sets` and `denied_permission_sets` to `access_roles` configuration, enabling AWS SSO permission sets to be granted or denied access to the Terraform state backend roles.

- **Organization ID trust policy optimization**: Added `use_organization_id` variable (default: `true`) to use `aws:PrincipalOrgID` condition in trust policies instead of listing individual account root ARNs. This addresses the IAM trust policy size limit (4096 characters) which can be exceeded in organizations with many accounts.

### Notes

- If using account names (not account IDs) in `access_roles`, you must provide the `account_map` variable with your account mappings
- The `use_organization_id` variable defaults to `true`, which is recommended for most deployments to avoid trust policy size limits
