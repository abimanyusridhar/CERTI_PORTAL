output "dynamodb_table_name" {
  value = aws_dynamodb_table.main.name
}

output "dynamodb_table_arn" {
  value = aws_dynamodb_table.main.arn
}

output "app_role_arn" {
  description = "Attach this to the app's compute (EC2 instance profile name below, or a container task role)."
  value       = aws_iam_role.app_role.arn
}

output "app_instance_profile_name" {
  value = var.ec2_instance_role ? aws_iam_instance_profile.app_role[0].name : null
}

output "app_crypto_keys_secret_arn" {
  description = "Set APP_KEYS_SECRET_ARN in .env to this once the app is updated to read from Secrets Manager."
  value       = aws_secretsmanager_secret.app_crypto_keys.arn
}

output "cognito_client_secret_arn" {
  description = "Populate this secret's value out-of-band (aws secretsmanager put-secret-value), then set COGNITO_CLIENT_SECRET_ARN in .env."
  value       = aws_secretsmanager_secret.cognito_client_secret.arn
}
