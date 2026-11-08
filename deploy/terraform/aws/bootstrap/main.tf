# One-time, per-account bootstrap of the Terraform remote state backend. Runs with local
# state (keep the resulting terraform.tfstate in the ops vault; it only describes the two
# resources below and contains no secrets).
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

locals {
  bucket_name = "${var.name_prefix}-tfstate-${var.environment}"
  table_name  = "${var.name_prefix}-tfstate-lock-${var.environment}"
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
      sse_algorithm = "AES256"
    }
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
    enabled = true
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
  }
}
