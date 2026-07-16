### Single-table DynamoDB store — see docs/data-structure-migration-plan.md
### and the Phase 1 plan for the full PK/SK schema. This table does not
### replace the JSON/S3 store on apply; it's created empty and populated via
### the dual-write rollout in server/repositories/dynamoStore.js +
### scripts/migrate-to-dynamo.js.

resource "aws_dynamodb_table" "main" {
  name         = var.dynamodb_table_name
  billing_mode = var.dynamodb_billing_mode
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # vessel-index: serves both "certs for vessel" and "groups containing
  # vessel" lookups that are currently a full in-memory scan (server/index.js
  # ~L2156-2161).
  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  global_secondary_index {
    name            = "vessel-index"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Environment = var.environment
    App         = "synergy-cert-portal"
  }
}
