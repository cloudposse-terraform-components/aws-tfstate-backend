locals {
  enabled = module.this.enabled

  # If S3 state lock is enabled, always disable DynamoDB
  dynamodb_enabled = var.s3_state_lock_enabled ? false : var.dynamodb_enabled
}

module "tfstate_backend" {
  source  = "cloudposse/tfstate-backend/aws"
  version = "1.7.0"

  enabled = local.enabled

  force_destroy                     = var.force_destroy
  prevent_unencrypted_uploads       = var.prevent_unencrypted_uploads
  enable_point_in_time_recovery     = var.enable_point_in_time_recovery
  bucket_ownership_enforced_enabled = false
  dynamodb_enabled                  = local.dynamodb_enabled
  s3_state_lock_enabled             = var.s3_state_lock_enabled

  context = module.this.context
}
