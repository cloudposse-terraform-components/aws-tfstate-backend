# Changelog

## Stop disabling `BucketOwnerEnforced` on the state bucket ([#80](https://github.com/cloudposse-terraform-components/aws-tfstate-backend/pull/80))

### Summary

The component hardcoded `bucket_ownership_enforced_enabled = false` when calling `cloudposse/tfstate-backend/aws`,
overriding that module's own default of `true`. The Terraform state bucket was therefore created with S3 Object
Ownership set to `BucketOwnerPreferred` and an `aws_s3_bucket_acl` resource attached, leaving ACLs a live
access-control mechanism on the bucket that holds every account's Terraform state. No variable stood behind the
setting, so it could not be overridden from stack configuration.

This release restores the module's default. Object Ownership is now `BucketOwnerEnforced`, ACLs are disabled, and
access is governed by the bucket policy and IAM alone. A new `bucket_ownership_enforced_enabled` variable (default
`true`) keeps the previous behaviour reachable for anyone who needs it.

### Breaking Changes

Existing deployments see a one-time change on the next `terraform apply`:

- `module.tfstate_backend.aws_s3_bucket_ownership_controls.default[0]` is updated in place, from
  `BucketOwnerPreferred` to `BucketOwnerEnforced`. Only `bucket` is `ForceNew` on that resource, so the bucket is
  not replaced.
- `module.tfstate_backend.aws_s3_bucket_acl.default[0]` is destroyed. `aws_s3_bucket_acl` has a no-op delete, so
  this removes the resource from Terraform state and makes no AWS API call.

No S3 objects are read, rewritten, or re-versioned: applying the bucket owner enforced setting does not add a new
version of an object. State reads and writes are unaffected, and no cold start or state migration is required.

### Impact

The bucket ACL this component created was the `private` canned ACL, which grants nothing beyond the bucket owner,
and the access roles this component creates grant `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`, and
`s3:DeleteObject` only — never `s3:PutObjectAcl` or `s3:GetObjectAcl`. Cross-account access to the backend has
always been granted by the bucket policy and IAM, not by ACLs, so disabling ACLs removes an unused mechanism rather
than a load-bearing one.

An Atmos `backend` or `remote_state_backend` configuration that sets `acl: bucket-owner-full-control` continues to
work. `BucketOwnerEnforced` accepts uploads that specify no ACL or the `bucket-owner-full-control` canned ACL, and
object ownership transfers to the bucket owner automatically, so the setting becomes redundant rather than broken.

What does break is granting access to the state bucket through bucket or object ACLs added outside this component.
That is not something this component has ever configured, but if you added such grants by hand, convert them to
bucket policy statements before applying.

### Action Required

None for most consumers. Apply the change and expect the two resource changes above.

To keep the previous behaviour, set the new variable explicitly:

```yaml
components:
  terraform:
    tfstate-backend:
      vars:
        bucket_ownership_enforced_enabled: false
```

### New Features

- **`bucket_ownership_enforced_enabled` variable**: Controls S3 Object Ownership on the state bucket (default:
  `true`). Previously hardcoded to `false` with no way to override it.

## Fix v2 Breaking Changes ([#57](https://github.com/cloudposse-terraform-components/aws-tfstate-backend/pull/57))

### Summary

This release fixes breaking changes unintentionally introduced in v2 when the `assume-role-policy` submodule replaced the shared `team-assume-role-policy` module from `account-map`. Several features were lost in that transition, causing IAM trust policies to be generated incorrectly for users with `account-map`.

### Breaking Change Fixes

- **Role ARN templates**: Fixed incorrect role ARN generation that used the deploying context (e.g., `use1-root`) instead of the target account context (e.g., `gbl-identity`). Role ARNs like `acme-core-use1-root-planners` are now correctly generated as `acme-core-gbl-identity-planners`.

- **Team permission sets**: Restored auto-generation of SSO permission set ARNs from identity account role names. Role names like `developers` are now converted to permission set patterns like `AWSReservedSSO_IdentityDevelopersTeamAccess_*`.

- **IAM user deny statement**: Restored the default deny statement for IAM users that was present in pre-v2 versions. This denies all IAM users except those explicitly allowed.

- **`use_organization_id` default**: The `use_organization_id` variable was introduced in v2 with an incorrect default of `true`. This PR corrects the default to `false` to match the pre-v2 behavior of listing individual account root ARNs.

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
