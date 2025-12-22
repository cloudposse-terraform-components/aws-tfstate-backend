# Changelog

## Fix v2 Breaking Changes ([#57](https://github.com/cloudposse-terraform-components/aws-tfstate-backend/pull/57))

### Summary

This release fixes breaking changes unintentionally introduced in v2 when the `assume-role-policy` submodule replaced the shared `team-assume-role-policy` module from `account-map`. Several features were lost in that transition, causing IAM trust policies to be generated incorrectly for users with `account-map`.

### Breaking Change Fixes

- **Role ARN templates**: Fixed incorrect role ARN generation that used the deploying context (e.g., `use1-root`) instead of the target account context (e.g., `gbl-identity`). Role ARNs like `acme-core-use1-root-planners` are now correctly generated as `acme-core-gbl-identity-planners`.

- **Team permission sets**: Restored auto-generation of SSO permission set ARNs from identity account role names. Role names like `developers` are now converted to permission set patterns like `AWSReservedSSO_IdentityDevelopersTeamAccess_*`.

- **IAM user deny statement**: Restored the default deny statement for IAM users that was present in pre-v2 versions. This denies all IAM users except those explicitly allowed.

- **`use_organization_id` default**: Changed default from `true` back to `false` to restore pre-v2 behavior.

### Impact by Customer Type

**Pre-v2 customers (with account_map):** Original behavior is restored. Changes should be minimal (ARN ordering, new resources).

**Post-v2 customers (without account_map):** A new `RoleDenyAssumeRole` statement will be added. This is a security improvement that should have been included in v2 initially. It denies all IAM users except explicitly allowed principals (e.g., SuperAdmin).

### Action Required

**For recent v2 adopters (implemented between v2 release and this patch):**

If you implemented `tfstate-backend` after v2 and want to preserve the v2 behavior for `use_organization_id`, you must explicitly set it in your stack configuration:

```yaml
components:
  terraform:
    tfstate-backend:
      vars:
        use_organization_id: true  # Preserve v2 behavior
```

Otherwise, trust policies will revert to listing individual account root ARNs instead of using the `aws:PrincipalOrgID` condition.

### New Features

- **`privileged` variable**: Added for remote state access without role assumption (e.g., when using SuperAdmin directly)
- **`team_permission_sets_enabled` variable**: Controls auto-generation of team permission sets (default: `true`)
- **`team_permission_set_name_pattern` variable**: Configurable pattern for team permission set names (default: `Identity%sTeamAccess`)

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
