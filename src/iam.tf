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
  caller_arn = coalesce(data.awsutils_caller_identity.current.eks_role_arn, data.awsutils_caller_identity.current.arn)
}

data "awsutils_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "current" {
  count = var.use_organization_id ? 1 : 0
}


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

# Build role ARN patterns from account IDs and role names
locals {
  # Helper map to convert account name/ID to account ID
  # If the key is already an account ID (numeric), use it as-is
  # Otherwise, look it up in the account_map
  to_account_id = try(var.account_map.full_account_map, {})

  # Convert account name/ID to account ID
  # Returns the account ID if the input is numeric (already an ID), otherwise looks it up in account_map
  # If account_map is not provided or account name not found, returns the key as-is (which will cause an error later)
  get_account_id = { for account_key in distinct(flatten([
    for role_config in values(local.access_roles) : concat(
      keys(role_config.allowed_roles),
      keys(role_config.denied_roles),
      keys(try(role_config.allowed_permission_sets, {})),
      keys(try(role_config.denied_permission_sets, {}))
    )
    ])) : account_key => (
    can(regex("^[0-9]{12}$", account_key)) ? account_key : (
      lookup(local.to_account_id, account_key, account_key)
    )
  ) }

  # Convert allowed_roles map (account_name/id -> [role_names]) to ARN patterns
  allowed_role_arns = {
    for role_key, role_config in local.access_roles : role_key => distinct(flatten([
      for account_key, role_names in role_config.allowed_roles : [
        for role_name in role_names : (
          role_name == "*" ?
          format("arn:%s:iam::%s:role/*", data.aws_partition.current.partition, local.get_account_id[account_key]) :
          format("arn:%s:iam::%s:role/%s-%s-%s-%s-%s", data.aws_partition.current.partition, local.get_account_id[account_key],
          module.this.namespace, module.this.environment, module.this.stage, module.this.name, role_name)
        )
      ]
    ]))
  }

  # Convert denied_roles map (account_name/id -> [role_names]) to ARN patterns
  denied_role_arns = {
    for role_key, role_config in local.access_roles : role_key => distinct(flatten([
      for account_key, role_names in role_config.denied_roles : [
        for role_name in role_names : (
          role_name == "*" ?
          format("arn:%s:iam::%s:role/*", data.aws_partition.current.partition, local.get_account_id[account_key]) :
          format("arn:%s:iam::%s:role/%s-%s-%s-%s-%s", data.aws_partition.current.partition, local.get_account_id[account_key],
          module.this.namespace, module.this.environment, module.this.stage, module.this.name, role_name)
        )
      ]
    ]))
  }

  # Convert allowed_permission_sets map (account_name/id -> [permission_set_names]) to ARN patterns
  # AWS SSO permission set IAM role ARN format: arn:aws:iam::ACCOUNT_ID:role/aws-reserved/sso.amazonaws.com/REGION/AWSReservedSSO_PERMISSION_SET_NAME_ID
  # The * wildcard matches the region path (e.g., /us-east-2) and the permission set instance ID suffix
  allowed_permission_set_arns = {
    for role_key, role_config in local.access_roles : role_key => distinct(flatten([
      for account_key, permission_sets in try(role_config.allowed_permission_sets, {}) : [
        for ps_name in permission_sets : format("arn:%s:iam::%s:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_%s_*",
        data.aws_partition.current.partition, local.get_account_id[account_key], ps_name)
      ]
    ]))
  }

  # Convert denied_permission_sets map (account_name/id -> [permission_set_names]) to ARN patterns
  denied_permission_set_arns = {
    for role_key, role_config in local.access_roles : role_key => distinct(flatten([
      for account_key, permission_sets in try(role_config.denied_permission_sets, {}) : [
        for ps_name in permission_sets : format("arn:%s:iam::%s:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_%s_*",
        data.aws_partition.current.partition, local.get_account_id[account_key], ps_name)
      ]
    ]))
  }

  # Extract account IDs from allowed_roles and allowed_permission_sets (after conversion)
  allowed_account_ids_from_roles = {
    for role_key, role_config in local.access_roles : role_key => distinct([
      for account_key in concat(
        keys(role_config.allowed_roles),
        keys(try(role_config.allowed_permission_sets, {}))
      ) : local.get_account_id[account_key]
    ])
  }

  # Extract account IDs from denied_roles and denied_permission_sets (after conversion)
  denied_account_ids = {
    for role_key, role_config in local.access_roles : role_key => distinct([
      for account_key in concat(
        keys(role_config.denied_roles),
        keys(try(role_config.denied_permission_sets, {}))
      ) : local.get_account_id[account_key]
    ])
  }

  # Parse ARNs for allowed principals to extract account IDs
  allowed_principal_accounts = {
    for role_key, role_config in local.access_roles : role_key => distinct([
      for arn in distinct(concat(role_config.allowed_principal_arns, [local.caller_arn])) : data.aws_arn.allowed_principals["${role_key}:${replace(arn, ":", "-")}"].account
    ])
  }

  # Combined denied principals (ARNs + role ARNs + permission set ARNs)
  denied_principals_combined = {
    for role_key, role_config in local.access_roles : role_key => distinct(concat(
      role_config.denied_principal_arns,
      try(local.denied_role_arns[role_key], []),
      try(local.denied_permission_set_arns[role_key], [])
    ))
  }

  # Principals that are allowed but not denied (exceptions to deny rule)
  undenied_principals = {
    for role_key, role_config in local.access_roles : role_key => distinct(tolist(setsubtract(
      toset(distinct(concat(role_config.allowed_principal_arns, [local.caller_arn]))),
      toset(role_config.denied_principal_arns)
    )))
  }
}

# Parse ARNs for allowed principals
data "aws_arn" "allowed_principals" {
  for_each = {
    for pair in flatten([
      for role_key, role_config in local.access_roles : [
        for arn in distinct(concat(role_config.allowed_principal_arns, [local.caller_arn])) : {
          key = "${role_key}:${replace(arn, ":", "-")}"
          arn = arn
        }
      ]
    ]) : pair.key => pair.arn
  }
  arn = each.value
}

# Trust policy document that replaces the account-map module dependency
data "aws_iam_policy_document" "assume_role" {
  for_each = local.access_roles_enabled ? local.access_roles : {}

  # Statement 1: Allow roles from specified accounts
  dynamic "statement" {
    for_each = length(local.allowed_account_ids_from_roles[each.key]) > 0 && length(local.allowed_role_arns[each.key]) > 0 ? [1] : []
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
        values   = ["AssumedRole"]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = local.allowed_role_arns[each.key]
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current.partition, local.allowed_account_ids_from_roles[each.key])
      }
    }
  }

  # Statement 2: Allow permission sets from specified accounts
  dynamic "statement" {
    for_each = length(local.allowed_account_ids_from_roles[each.key]) > 0 && length(local.allowed_permission_set_arns[each.key]) > 0 ? [1] : []
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
        values   = local.allowed_permission_set_arns[each.key]
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current.partition, local.allowed_account_ids_from_roles[each.key])
      }
    }
  }

  # Statement 3: Allow explicit principal ARNs
  dynamic "statement" {
    for_each = length(local.allowed_principal_accounts[each.key]) > 0 && length(distinct(concat(each.value.allowed_principal_arns, [local.caller_arn]))) > 0 ? [1] : []
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
        values   = distinct(concat(each.value.allowed_principal_arns, [local.caller_arn]))
      }

      principals {
        type        = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current.partition, local.allowed_principal_accounts[each.key])
      }
    }
  }

  # Statement 4: Deny explicitly denied principals, roles, and permission sets
  # Only create this statement if there are actually denied principals
  dynamic "statement" {
    for_each = length(local.denied_principals_combined[each.key]) > 0 ? [1] : []
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
        values   = local.denied_principals_combined[each.key]
      }

      dynamic "condition" {
        for_each = length(local.undenied_principals[each.key]) > 0 ? [1] : []
        content {
          test     = "ArnNotEquals"
          variable = "aws:PrincipalArn"
          values   = local.undenied_principals[each.key]
        }
      }

      principals {
        type = "AWS"
        identifiers = var.use_organization_id ? ["*"] : formatlist("arn:%s:iam::%s:root", data.aws_partition.current.partition, distinct(concat(
          local.allowed_account_ids_from_roles[each.key],
          local.allowed_principal_accounts[each.key],
          local.denied_account_ids[each.key]
        )))
      }
    }
  }
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
  assume_role_policy = var.access_roles_enabled ? data.aws_iam_policy_document.assume_role[each.key].json : data.aws_iam_policy_document.cold_start_assume_role[each.key].json
  tags               = merge(module.this.tags, { Name = each.key })
}

resource "aws_iam_role_policy" "default" {
  for_each = local.access_roles

  name   = each.key
  role   = aws_iam_role.default[each.key].id
  policy = data.aws_iam_policy_document.tfstate[each.key].json
}

locals {
  all_cold_start_access_principals = local.cold_start_access_enabled ? toset(concat([local.caller_arn],
  flatten([for k, v in local.access_roles : v.allowed_principal_arns]))) : toset([])
  cold_start_access_principal_arns = local.cold_start_access_enabled ? { for k, v in local.access_roles : k => distinct(concat(
    [local.caller_arn], v.allowed_principal_arns
  )) } : {}
  cold_start_access_principals = local.cold_start_access_enabled ? {
    for k, v in local.cold_start_access_principal_arns : k => formatlist("arn:%v:iam::%v:root", data.aws_partition.current.partition, distinct([
      for arn in v : data.aws_arn.cold_start_access[arn].account
    ]))
  } : {}

}

data "aws_arn" "cold_start_access" {
  for_each = local.all_cold_start_access_principals
  arn      = each.value
}

# This is a basic policy that allows the caller and explicitly allowed principals to assume the role
# during the period roles are being set up (cold start).
data "aws_iam_policy_document" "cold_start_assume_role" {
  for_each = local.cold_start_access_enabled ? local.access_roles : {}

  statement {
    sid = "ColdStartRoleAssumeRole"

    effect = "Allow"
    # These actions need to be kept in sync with the actions in the assume_role policy document
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
