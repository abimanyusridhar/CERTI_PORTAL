### Least-privilege IAM role for the app process — no wildcards, no
### s3:ListBucket, no dynamodb:Scan. Replaces the static-access-key IAM user
### documented in AWS-MIGRATION-GUIDE.md (synergy-cert-portal-s3): that guide
### predates this module and should be treated as superseded once this role
### is in place and the app is redeployed to use it instead of static keys.

data "aws_iam_policy_document" "app_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app_role" {
  name               = var.app_role_name
  assume_role_policy = data.aws_iam_policy_document.app_assume_role.json

  tags = {
    Environment = var.environment
    App         = "synergy-cert-portal"
  }
}

data "aws_iam_policy_document" "app_role_policy" {
  statement {
    sid    = "DynamoDbTableAndIndexOnly"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
    ]
    resources = [
      aws_dynamodb_table.main.arn,
      "${aws_dynamodb_table.main.arn}/index/vessel-index",
    ]
  }

  statement {
    sid    = "S3TenantPrefixedDataAndUploads"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = concat(
      [for prefix in var.tenant_prefixes : "${data.aws_s3_bucket.uploads.arn}/data/${prefix}/*"],
      [for prefix in var.tenant_prefixes : "${data.aws_s3_bucket.uploads.arn}/uploads/${prefix}/*"],
    )
  }

  statement {
    sid       = "SecretsManagerReadOnlyOwnSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.app_crypto_keys.arn,
      aws_secretsmanager_secret.cognito_client_secret.arn,
    ]
  }

  dynamic "statement" {
    for_each = var.s3_kms_key_arn != "" ? [1] : []
    content {
      sid       = "KmsForSseOnUploadsBucket"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources = [var.s3_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "app_role_policy" {
  name   = "${var.app_role_name}-policy"
  role   = aws_iam_role.app_role.id
  policy = data.aws_iam_policy_document.app_role_policy.json
}

resource "aws_iam_instance_profile" "app_role" {
  count = var.ec2_instance_role ? 1 : 0
  name  = var.app_role_name
  role  = aws_iam_role.app_role.name
}
