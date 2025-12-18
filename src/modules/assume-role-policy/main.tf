# This module generates an IAM assume role policy document.
# It accepts pre-resolved account IDs via the account_map variable, or account IDs can be specified directly.

locals {
  enabled = module.this.enabled

  # Helper map to convert account name/ID to account ID
  # If the key is already an account ID (numeric), use it as-is
  # Otherwise, look it up in the account_map
  to_account_id = try(var.account_map.full_account_map, {})

  # Collect all account keys referenced in any of the role/permission set maps
  all_account_keys = distinct(flatten([
    keys(var.allowed_roles),
    keys(var.denied_roles),
    keys(var.allowed_permission_sets),
    keys(var.denied_permission_sets)
  ]))

  # Validate that all account keys are either 12-digit account IDs or exist in the account_map
  # This prevents silent failures where unmapped account names produce invalid ARNs
  invalid_account_keys = [
    for key in local.all_account_keys : key
    if !can(regex("^[0-9]{12}$", key)) && !contains(keys(local.to_account_id), key)
  ]

  # This will cause a plan-time error if any invalid keys are found
  validate_account_keys = (
    length(local.invalid_account_keys) == 0 ? true : tobool(
      "Invalid account keys found: [${join(", ", local.invalid_account_keys)}]. " +
      "Each key must be either a 12-digit AWS account ID or a valid account name in account_map.full_account_map."
    )
  )

  # Convert account name/ID to account ID
  # Returns the account ID if the input is numeric (already an ID), otherwise looks it up in account_map
  # The validation check is included in the condition to ensure it runs before any lookups
  get_account_id = local.validate_account_keys ? { for account_key in local.all_account_keys : account_key => (
    can(regex("^[0-9]{12}$", account_key)) ? account_key : local.to_account_id[account_key]
  ) } : {}

  # Convert allowed_roles map (account_name/id -> [role_names]) to ARN patterns
  # Template uses two placeholders: first %s = account name, second %s = role name
  allowed_role_arns = local.enabled ? distinct(flatten([
    for account_key, role_names in var.allowed_roles : [
      for role_name in role_names : (
        role_name == "*" ?
        format("arn:%s:iam::%s:role/*", data.aws_partition.current[0].partition, local.get_account_id[account_key]) :
        format("arn:%s:iam::%s:role/%s", data.aws_partition.current[0].partition, local.get_account_id[account_key],
        var.iam_role_arn_template != null ? format(var.iam_role_arn_template, account_key, role_name) : role_name)
      )
    ]
  ])) : []

  # Convert denied_roles map (account_name/id -> [role_names]) to ARN patterns
  # Template uses two placeholders: first %s = account name, second %s = role name
  denied_role_arns = local.enabled ? distinct(flatten([
    for account_key, role_names in var.denied_roles : [
      for role_name in role_names : (
        role_name == "*" ?
        format("arn:%s:iam::%s:role/*", data.aws_partition.current[0].partition, local.get_account_id[account_key]) :
        format("arn:%s:iam::%s:role/%s", data.aws_partition.current[0].partition, local.get_account_id[account_key],
        var.iam_role_arn_template != null ? format(var.iam_role_arn_template, account_key, role_name) : role_name)
      )
    ]
  ])) : []

  # Convert allowed_permission_sets map (account_name/id -> [permission_set_names]) to ARN patterns
  # AWS SSO permission set IAM role ARN format: arn:aws:iam::ACCOUNT_ID:role/aws-reserved/sso.amazonaws.com/REGION/AWSReservedSSO_PERMISSION_SET_NAME_ID
  # The * wildcard matches the region path (e.g., /us-east-2) and the permission set instance ID suffix
  allowed_permission_set_arns = local.enabled ? distinct(flatten([
    for account_key, permission_sets in var.allowed_permission_sets : [
      for ps_name in permission_sets : format("arn:%s:iam::%s:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_%s_*",
      data.aws_partition.current[0].partition, local.get_account_id[account_key], ps_name)
    ]
  ])) : []

  # Convert denied_permission_sets map (account_name/id -> [permission_set_names]) to ARN patterns
  denied_permission_set_arns = local.enabled ? distinct(flatten([
    for account_key, permission_sets in var.denied_permission_sets : [
      for ps_name in permission_sets : format("arn:%s:iam::%s:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_%s_*",
      data.aws_partition.current[0].partition, local.get_account_id[account_key], ps_name)
    ]
  ])) : []

  # Combined denied principals (ARNs + role ARNs + permission set ARNs)
  denied_principals_combined = distinct(concat(
    var.denied_principal_arns,
    local.denied_role_arns,
    local.denied_permission_set_arns
  ))

  # Extract account IDs from allowed_roles and allowed_permission_sets (after conversion)
  allowed_account_ids_from_roles = distinct([
    for account_key in concat(keys(var.allowed_roles), keys(var.allowed_permission_sets)) : local.get_account_id[account_key]
  ])

  # Extract account IDs from denied_roles and denied_permission_sets (after conversion)
  denied_account_ids = distinct([
    for account_key in concat(keys(var.denied_roles), keys(var.denied_permission_sets)) : local.get_account_id[account_key]
  ])

  # Parse ARNs for allowed principals to extract account IDs
  allowed_principal_accounts = local.enabled ? distinct([
    for arn in var.allowed_principal_arns : data.aws_arn.allowed_principals[arn].account
  ]) : []

  # Principals that are allowed but not denied (exceptions to deny rule)
  undenied_principals = distinct(tolist(setsubtract(
    toset(var.allowed_principal_arns),
    toset(var.denied_principal_arns)
  )))

  # Whether to generate the policy
  assume_role_enabled = local.enabled && (
    length(local.allowed_account_ids_from_roles) > 0 ||
    length(local.allowed_principal_accounts) > 0 ||
    length(local.denied_account_ids) > 0
  )
}

data "aws_partition" "current" {
  count = local.enabled ? 1 : 0
}

data "aws_organizations_organization" "current" {
  count = local.enabled && var.use_organization_id ? 1 : 0
}

# Parse ARNs for allowed principals
data "aws_arn" "allowed_principals" {
  for_each = local.enabled ? toset(var.allowed_principal_arns) : toset([])
  arn      = each.value
}

# Trust policy document
data "aws_iam_policy_document" "assume_role" {
  count = local.assume_role_enabled ? 1 : 0

  # Statement 1: Allow roles from specified accounts
  dynamic "statement" {
    for_each = length(local.allowed_account_ids_from_roles) > 0 && length(local.allowed_role_arns) > 0 ? [1] : []
    content {
      sid    = "RoleAssumeRole"
      effect = "Allow"
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
        test     = "StringEquals"
        variable = "aws:PrincipalType"
        values   = compact(concat(["AssumedRole"], var.iam_users_enabled ? ["User"] : []))
      }
      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = local.allowed_role_arns
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current[0].partition, local.allowed_account_ids_from_roles)
      }
    }
  }

  # Statement 2: Allow permission sets from specified accounts
  dynamic "statement" {
    for_each = length(local.allowed_account_ids_from_roles) > 0 && length(local.allowed_permission_set_arns) > 0 ? [1] : []
    content {
      sid    = "PermissionSetAssumeRole"
      effect = "Allow"
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
        test     = "StringEquals"
        variable = "aws:PrincipalType"
        values   = ["AssumedRole"]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = local.allowed_permission_set_arns
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current[0].partition, local.allowed_account_ids_from_roles)
      }
    }
  }

  # Statement 3: Allow explicit principal ARNs
  dynamic "statement" {
    for_each = length(local.allowed_principal_accounts) > 0 && length(var.allowed_principal_arns) > 0 ? [1] : []
    content {
      sid    = "PrincipalAssumeRole"
      effect = "Allow"
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
        values   = var.allowed_principal_arns
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current[0].partition, local.allowed_principal_accounts)
      }
    }
  }

  # Statement 4: Deny explicitly denied principals, roles, and permission sets
  # Only create this statement if there are actually denied principals
  dynamic "statement" {
    for_each = length(local.denied_principals_combined) > 0 ? [1] : []
    content {
      sid    = "RoleDenyAssumeRole"
      effect = "Deny"
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
        values   = local.denied_principals_combined
      }

      dynamic "condition" {
        for_each = length(local.undenied_principals) > 0 ? [1] : []
        content {
          test     = "ArnNotEquals"
          variable = "aws:PrincipalArn"
          values   = local.undenied_principals
        }
      }

      principals {
        type = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current[0].partition, distinct(concat(
          local.allowed_account_ids_from_roles,
          local.allowed_principal_accounts,
          local.denied_account_ids
        )))
      }
    }
  }
}
