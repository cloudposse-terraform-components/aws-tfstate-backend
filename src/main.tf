locals {
  enabled = module.this.enabled
}

module "tfstate_backend" {
  source  = "cloudposse/tfstate-backend/aws"
  version = "1.5.0"

  force_destroy                     = var.force_destroy
  prevent_unencrypted_uploads       = var.prevent_unencrypted_uploads
  enable_point_in_time_recovery     = var.enable_point_in_time_recovery
  bucket_ownership_enforced_enabled = false
  dynamodb_enabled                  = var.dynamodb_enabled

  context = module.this.context
}
