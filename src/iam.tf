locals {
  access_roles = local.enabled ? {
    for k, v in var.access_roles : (
      length(split(module.this.delimiter, k)) > 1 ? k : module.label[k].id
    ) => v
  } : {}

  access_roles_enabled      = local.enabled && var.access_roles_enabled
  cold_start_access_enabled = local.enabled && !var.access_roles_enabled

  # Technically, `eks_role_arn` is incorrect, because it strips any path from the ARN,
  # but since we do not expect there to be a path in the role ARN (as opposed to perhaps an attached IAM policy),
  # it is OK. The advantage of using `eks_role_arn` is that it converts and Assumed Role ARN from STS, like
  #    arn:aws:sts::123456789012:assumed-role/acme-core-gbl-root-admin/aws-go-sdk-1722029959251053170
  # to the IAM Role ARN, like
  #    arn:aws:iam::123456789012:role/acme-core-gbl-root-admin
  caller_arn_raw = coalesce(data.awsutils_caller_identity.current.eks_role_arn, data.awsutils_caller_identity.current.arn)

  # Check if the caller is an SSO permission set role
  caller_is_sso_role = can(regex("AWSReservedSSO_", local.caller_arn_raw))

  # For SSO permission set roles, extract the account ID and permission set name.
  # These are added to allowed_permission_sets (not allowed_principal_arns) to avoid drift
  # when different users with the same permission set run terraform.
  #
  # SSO role ARNs can appear in two formats:
  #   - Path-stripped: arn:aws:iam::123456789012:role/AWSReservedSSO_TerraformApplyAccess_bd2360a3f5507778
  #   - Full path:     arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_TerraformApplyAccess_bd2360a3f5507778
  #
  # The regex handles both formats with an optional path segment.
  # Captured groups: [0]=partition, [1]=account_id, [2]=permission_set_name, [3]=instance_id (unused)
  caller_sso_parts = local.caller_is_sso_role ? regex(
    "^arn:([^:]+):iam::([0-9]+):role/(?:aws-reserved/sso\\.amazonaws\\.com(?:/[^/]+)?/)?AWSReservedSSO_(.+)_([a-f0-9]{16})$",
    local.caller_arn_raw
  ) : null

  # For non-SSO callers, use the raw ARN directly
  # For SSO callers, this will be null (they go into allowed_permission_sets instead)
  caller_arn = local.caller_is_sso_role ? null : local.caller_arn_raw

  # For SSO callers, extract account ID and permission set name to add to allowed_permission_sets
  caller_permission_set = local.caller_is_sso_role ? {
    (local.caller_sso_parts[1]) = [local.caller_sso_parts[2]] # account_id = [permission_set_name]
  } : {}

  # Fallback IAM role name template used when per-account templates are not available
  # (i.e., when account_map_enabled is false and no iam_role_arn_templates provided)
  # Format: {namespace}-{tenant}-gbl-{account}-{role} (e.g., acme-core-gbl-identity-admin)
  # Uses "gbl" for environment since IAM roles are global resources
  #
  # When account_map_enabled is true, the account-map component provides per-account
  # iam_role_arn_templates which take precedence over this fallback template.
  iam_role_arn_template = join(module.this.delimiter, compact([
    module.this.namespace,
    module.this.tenant,
    "gbl",
    "%s", # account name placeholder
    "%s"  # role name placeholder
  ]))
}

data "awsutils_caller_identity" "current" {}
data "aws_partition" "current" {}

module "label" {
  for_each = local.enabled ? var.access_roles : {}
  source   = "cloudposse/label/null"
  version  = "0.25.0" # requires Terraform >= 0.13.0

  enabled = length(split(module.this.delimiter, each.key)) == 1

  environment = "gbl"
  attributes  = contains(["default", "terraform"], each.key) ? [] : [each.key]
  # Support backward compatibility with old `iam-delegated-roles`
  name = each.key == "terraform" ? "terraform" : null

  context = module.this.context
}

# Use the assume-role-policy submodule to generate trust policies
module "assume_role" {
  for_each = local.access_roles_enabled ? local.access_roles : {}
  source   = "./modules/assume-role-policy"

  allowed_roles          = each.value.allowed_roles
  denied_roles           = each.value.denied_roles
  allowed_principal_arns = distinct(concat(each.value.allowed_principal_arns, compact([local.caller_arn])))
  denied_principal_arns  = each.value.denied_principal_arns
  # Merge permission sets with proper list union per account (not simple merge which would replace lists)
  allowed_permission_sets = {
    for account_id in distinct(concat(
      keys(try(each.value.allowed_permission_sets, {})),
      keys(local.caller_permission_set)
      )) : account_id => distinct(concat(
      try(each.value.allowed_permission_sets[account_id], []),
      try(local.caller_permission_set[account_id], [])
    ))
  }
  denied_permission_sets = try(each.value.denied_permission_sets, {})

  account_map           = module.account_map.outputs
  use_organization_id   = var.use_organization_id
  iam_role_arn_template = local.iam_role_arn_template

  context = module.this.context
}

data "aws_iam_policy_document" "tfstate" {
  for_each = local.access_roles

  statement {
    sid     = "TerraformStateBackendS3Bucket"
    effect  = "Allow"
    actions = concat(["s3:ListBucket", "s3:GetObject"], each.value.write_enabled ? ["s3:PutObject", "s3:DeleteObject"] : [])
    resources = [
      module.tfstate_backend.s3_bucket_arn,
      "${module.tfstate_backend.s3_bucket_arn}/*"
    ]
  }

  dynamic "statement" {
    for_each = local.dynamodb_enabled ? [1] : []
    content {
      sid    = "TerraformStateBackendDynamoDbTable"
      effect = "Allow"
      # Even readers need to be able to write to the Dynamo table to lock the state while planning
      # actions   = concat(["dynamodb:GetItem"], each.value.write_enabled ? ["dynamodb:PutItem", "dynamodb:DeleteItem"] : [])
      actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
      resources = [module.tfstate_backend.dynamodb_table_arn]
    }
  }
}

resource "aws_iam_role" "default" {
  for_each = local.access_roles

  name               = each.key
  description        = "${each.value.write_enabled ? "Access" : "Read-only access"} role for ${module.this.id}"
  assume_role_policy = var.access_roles_enabled ? module.assume_role[each.key].policy_document : data.aws_iam_policy_document.cold_start_assume_role[each.key].json
  tags               = merge(module.this.tags, { Name = each.key })
}

resource "aws_iam_role_policy" "default" {
  for_each = local.access_roles

  name   = each.key
  role   = aws_iam_role.default[each.key].id
  policy = data.aws_iam_policy_document.tfstate[each.key].json
}

# Cold start access policy - used when access_roles_enabled is false
# This allows the caller and explicitly allowed principals to assume the role during initial setup
locals {
  # Filter out wildcard ARNs - they can't be used to derive account root principals
  # Wildcard ARNs are still used in the ArnLike condition, but principals must be concrete
  # Note: Use caller_arn_raw here since caller_arn is null for SSO callers (they're handled via allowed_permission_sets)
  all_cold_start_access_principals_raw = local.cold_start_access_enabled ? toset(concat([local.caller_arn_raw],
  flatten([for k, v in local.access_roles : v.allowed_principal_arns]))) : toset([])
  all_cold_start_access_principals = toset([for arn in local.all_cold_start_access_principals_raw : arn if !strcontains(arn, "*")])

  cold_start_access_principal_arns = local.cold_start_access_enabled ? { for k, v in local.access_roles : k => distinct(concat(
    [local.caller_arn_raw], v.allowed_principal_arns
  )) } : {}

  # Only use non-wildcard ARNs for deriving account root principals
  cold_start_access_principals = local.cold_start_access_enabled ? {
    for k, v in local.cold_start_access_principal_arns : k => formatlist("arn:%v:iam::%v:root", data.aws_partition.current.partition, distinct([
      for arn in v : data.aws_arn.cold_start_access[arn].account if !strcontains(arn, "*")
    ]))
  } : {}
}

data "aws_arn" "cold_start_access" {
  for_each = local.all_cold_start_access_principals
  arn      = each.value
}

data "aws_organizations_organization" "current" {
  count = local.cold_start_access_enabled && var.use_organization_id ? 1 : 0
}

# This is a basic policy that allows the caller and explicitly allowed principals to assume the role
# during the period roles are being set up (cold start).
data "aws_iam_policy_document" "cold_start_assume_role" {
  for_each = local.cold_start_access_enabled ? local.access_roles : {}

  statement {
    sid = "ColdStartRoleAssumeRole"

    effect = "Allow"
    # These actions need to be kept in sync with the actions in the assume_role module
    actions = [
      "sts:AssumeRole",
      "sts:SetSourceIdentity",
      "sts:TagSession",
    ]

    dynamic "condition" {
      for_each = var.use_organization_id ? [1] : []
      content {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [data.aws_organizations_organization.current[0].id]
      }
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.cold_start_access_principal_arns[each.key]
    }

    principals {
      type = "AWS"
      # Principals is a required field, so we allow any principal in any of the accounts, restricted by the assumed Role ARN in the condition clauses.
      # This allows us to allow non-existent (yet to be created) roles, which would not be allowed if directly specified in `principals`.
      identifiers = var.use_organization_id ? ["*"] : local.cold_start_access_principals[each.key]
    }
  }
}
