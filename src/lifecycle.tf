# Lifecycle configuration for the state bucket. The upstream module creates
# none (a bucket can have only one), so the versioned bucket otherwise keeps
# every noncurrent state version.
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  count = local.enabled && var.lifecycle_enabled ? 1 : 0

  bucket = module.tfstate_backend.s3_bucket_id

  rule {
    id     = "tfstate-noncurrent-versions"
    status = "Enabled"

    # Every object in the bucket. Current objects are never expired.
    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.noncurrent_version_expiration_days
      newer_noncurrent_versions = var.noncurrent_versions_to_keep
    }

    # Delete markers left by S3 native lock release, once their noncurrent
    # versions are gone.
    expiration {
      expired_object_delete_marker = true
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  lifecycle {
    precondition {
      condition     = !var.s3_state_lock_enabled || var.noncurrent_version_expiration_days > 7
      error_message = "With s3_state_lock_enabled the bucket has a 7-day Object Lock retention; noncurrent_version_expiration_days must exceed 7."
    }
  }
}
