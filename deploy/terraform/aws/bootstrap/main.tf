# One-time, per-account bootstrap of the Terraform remote state backend. Runs with local
# state (keep the resulting terraform.tfstate in the ops vault; it only describes the bucket,
# the lock table and their KMS key below and contains no secrets).
#
#   cd deploy/terraform/aws/bootstrap
#   terraform init
#   terraform apply -var environment=staging -var region=eu-west-1
#
# The outputs are the values for ../environments/<env>.backend.hcl.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80.0, < 6.0.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "IronMesh"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

variable "environment" {
  description = "staging | prod."
  type        = string

  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be staging or prod."
  }
}

variable "region" {
  description = "Region of the state bucket and lock table."
  type        = string
}

variable "name_prefix" {
  description = "Project prefix."
  type        = string
  default     = "ironmesh"
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  bucket_name  = "${var.name_prefix}-tfstate-${var.environment}"
  table_name   = "${var.name_prefix}-tfstate-lock-${var.environment}"
  account_root = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"

  # Administrative actions only (no Encrypt/Decrypt/GenerateDataKey).
  state_key_admin_actions = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListKeyPolicies",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
  ]
}

#------------------------------------------------------------------------------
# Customer-managed key for the state bucket and the lock table. Administration is delegated
# to IAM in this account; data-key use is limited to S3 and DynamoDB calls from this account.
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "state_key" {
  statement {
    sid       = "KeyAdministrationThroughIam"
    actions   = local.state_key_admin_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }

  statement {
    sid       = "StateEncryptionViaS3AndDynamoDb"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com", "dynamodb.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "IronMesh Terraform state (${var.environment}): S3 bucket and DynamoDB lock table"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 365
  policy                  = data.aws_iam_policy_document.state_key.json

  tags = {
    Name = local.bucket_name
  }
}

resource "aws_kms_alias" "state" {
  name          = "alias/${local.bucket_name}"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket = local.bucket_name

  tags = {
    Name = local.bucket_name
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

resource "aws_dynamodb_table" "lock" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.state.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = local.table_name
  }
}

output "backend_config" {
  description = "Values for environments/<env>.backend.hcl."
  value = {
    bucket         = aws_s3_bucket.state.bucket
    key            = "aws/${var.environment}/terraform.tfstate"
    region         = var.region
    dynamodb_table = aws_dynamodb_table.lock.name
    encrypt        = true
    kms_key_id     = aws_kms_key.state.arn
  }
}
