output "policy_document" {
  description = "JSON encoded string representing the assume role policy configured by the inputs"
  value       = join("", data.aws_iam_policy_document.assume_role[*].json)
}

output "policy_document_json" {
  description = "The assume role policy as a Terraform object (for use with jsonencode or further manipulation)"
  value       = local.assume_role_enabled ? jsondecode(data.aws_iam_policy_document.assume_role[0].json) : null
}

output "allowed_role_arns" {
  description = "List of allowed role ARN patterns"
  value       = local.allowed_role_arns
}

output "allowed_permission_set_arns" {
  description = "List of allowed permission set ARN patterns"
  value       = local.allowed_permission_set_arns
}

output "denied_principals_combined" {
  description = "Combined list of all denied principal ARN patterns"
  value       = local.denied_principals_combined
}
