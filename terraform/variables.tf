variable "aws_region" {
  description = "AWS region the app already runs in (matches AWS_REGION / S3_REGION in .env)."
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Short environment/deployment name, used to namespace resource names (e.g. prod, staging)."
  type        = string
  default     = "prod"
}

variable "s3_bucket_name" {
  description = <<-EOT
    Name of the EXISTING S3 bucket the app already uses (see AWS-MIGRATION-GUIDE.md).
    This module does not create the bucket — it only attaches encryption defaults
    and a least-privilege bucket policy to it, so applying this does not risk the
    bucket's existing contents, versioning, or lifecycle config.
  EOT
  type = string
}

variable "s3_kms_key_arn" {
  description = <<-EOT
    Optional customer-managed KMS key ARN for SSE-KMS on the uploads bucket. Leave
    empty to use SSE-S3 (AES256) instead, which needs no key management.
  EOT
  type    = string
  default = ""
}

variable "tenant_prefixes" {
  description = <<-EOT
    Tenant-scoped key prefixes the app's IAM role needs S3 access to, matching the
    existing data/<TENANT_ID>/ and uploads/<TENANT_ID>/ path convention. Use ["*"]
    only for single-tenant deployments; for multi-tenant, list each TENANT_ID.
  EOT
  type    = list(string)
  default = ["*"]
}

variable "dynamodb_table_name" {
  description = "Name of the single-table DynamoDB store (certificates, users, groups, documents, audit events)."
  type        = string
  default     = "synergy-cert-portal"
}

variable "dynamodb_billing_mode" {
  description = "PAY_PER_REQUEST avoids capacity planning during the dual-write/shadow-read migration window."
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "app_role_name" {
  description = "Name of the least-privilege IAM role the app assumes (e.g. via an EC2 instance profile)."
  type        = string
  default     = "synergy-cert-portal-app-role"
}

variable "ec2_instance_role" {
  description = <<-EOT
    Set to true to also create an EC2 instance profile wrapping app_role, so the
    running instance can assume it without static AWS keys. Set to false if the
    role will be assumed a different way (e.g. from a container task role you
    manage elsewhere) — in that case, adjust the assume-role policy in iam.tf.
  EOT
  type    = bool
  default = true
}
