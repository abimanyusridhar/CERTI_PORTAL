### Secrets Manager — moves the two secrets currently living as plaintext
### (a self-generated .keys.json file mirrored to S3 as a plaintext blob via
### _syncKeysWithS3 in server/index.js, and COGNITO_CLIENT_SECRET in .env)
### to a managed, access-logged, rotatable store. Secret VALUES are not set
### here — Terraform creates empty secret shells; the app populates
### app_crypto_keys on first boot (matching its existing self-generation
### behavior) and Cognito's client secret is entered once via
### `aws secretsmanager put-secret-value` (or the console) outside of state,
### so it never touches a .tf file or the Terraform state diff.

resource "aws_secretsmanager_secret" "app_crypto_keys" {
  name        = "${var.app_role_name}/crypto-keys-${var.environment}"
  description = "App-generated HMAC/JWT signing keys (replaces plaintext .keys.json in S3)."
}

resource "aws_secretsmanager_secret" "cognito_client_secret" {
  name        = "${var.app_role_name}/cognito-client-secret-${var.environment}"
  description = "Cognito app client secret (replaces plaintext COGNITO_CLIENT_SECRET in .env)."
}
