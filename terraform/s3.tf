### S3 hardening — attaches to the EXISTING bucket (see AWS-MIGRATION-GUIDE.md).
### Does not create, delete, or alter the bucket's contents, versioning, or
### lifecycle rules. Two changes only:
###   1. Enforce default server-side encryption bucket-wide (currently opt-in —
###      the app only sends SSE headers if S3_SSE is set in .env, so an upload
###      made before that env var existed, or from any other writer, was
###      unencrypted-by-default).
###   2. A bucket policy scoped to the app's own IAM role, least-privilege by
###      tenant-prefixed key paths — no public access, no wildcard resources.

data "aws_s3_bucket" "uploads" {
  bucket = var.s3_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = data.aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.s3_kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.s3_kms_key_arn != "" ? var.s3_kms_key_arn : null
    }
    # bucket_key_enabled reduces KMS request cost/throttling on high-volume
    # uploads; irrelevant (and omitted) for the SSE-S3/AES256 case.
    bucket_key_enabled = var.s3_kms_key_arn != "" ? true : null
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = data.aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Scoped to the tenant-prefixed data/ and uploads/ paths already used by
# server/repositories/s3JsonStore.js and server/services/s3.js — never
# bucket-wide, and only for the app's own role (no public statements).
data "aws_iam_policy_document" "uploads_bucket_policy" {
  statement {
    sid    = "AppRoleReadWriteTenantPrefixes"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.app_role.arn]
    }
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [
      for prefix in var.tenant_prefixes :
      "${data.aws_s3_bucket.uploads.arn}/data/${prefix}/*"
    ]
  }

  statement {
    sid    = "AppRoleReadWriteTenantUploads"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.app_role.arn]
    }
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [
      for prefix in var.tenant_prefixes :
      "${data.aws_s3_bucket.uploads.arn}/uploads/${prefix}/*"
    ]
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [data.aws_s3_bucket.uploads.arn, "${data.aws_s3_bucket.uploads.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = data.aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_bucket_policy.json
}
