locals {
  enabled = module.this.enabled

  # If S3 state lock is enabled, always disable DynamoDB
  dynamodb_enabled = var.s3_state_lock_enabled ? false : var.dynamodb_enabled
}

module "tfstate_backend" {
  source  = "cloudposse/tfstate-backend/aws"
  version = "1.7.1"

  enabled = local.enabled

  force_destroy                     = var.force_destroy
  prevent_unencrypted_uploads       = var.prevent_unencrypted_uploads
  enable_point_in_time_recovery     = var.enable_point_in_time_recovery
  bucket_ownership_enforced_enabled = false
  dynamodb_enabled                  = local.dynamodb_enabled
  s3_state_lock_enabled             = var.s3_state_lock_enabled

  sse_encryption    = var.sse_encryption
  kms_master_key_id = var.kms_master_key_id
  logging           = var.logging == null ? [] : [var.logging]

  s3_replication_enabled = var.s3_replication_enabled
  s3_replica_bucket_arn  = var.s3_replica_bucket_arn

  context = module.this.context
}
