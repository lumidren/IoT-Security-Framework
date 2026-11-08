locals {
  artifacts_bucket = "${var.name_prefix}-firmware-${var.account_id}-${var.region}"
  replica_bucket   = "${var.name_prefix}-firmware-replica-${var.account_id}-${var.replica_region}"
  backups_bucket   = "${var.name_prefix}-backups-${var.account_id}-${var.region}"
  logs_bucket      = "${var.name_prefix}-logs-${var.account_id}-${var.region}"
}

data "aws_elb_service_account" "this" {}

#------------------------------------------------------------------------------
# Shared policy fragments
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "deny_insecure" {
  for_each = {
    artifacts = local.artifacts_bucket
    backups   = local.backups_bucket
    logs      = local.logs_bucket
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:${var.partition}:s3:::${each.value}", "arn:${var.partition}:s3:::${each.value}/*"]

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

# Uploads must declare SSE-KMS with the IronMesh key explicitly (default encryption alone
# would silently accept a request that asked for a different key).
data "aws_iam_policy_document" "require_kms" {
  for_each = {
    artifacts = local.artifacts_bucket
    backups   = local.backups_bucket
  }

  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:${var.partition}:s3:::${each.value}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyWrongKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:${var.partition}:s3:::${each.value}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }
  }
}

#------------------------------------------------------------------------------
# Firmware artifacts
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket              = local.artifacts_bucket
  object_lock_enabled = true

  tags = {
    Name = local.artifacts_bucket
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Release artifacts cannot be deleted or overwritten for the retention period, even by the
# bucket owner, unless the caller has s3:BypassGovernanceRetention (reserved for break-glass).
resource "aws_s3_bucket_object_lock_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.artifact_object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "firmware-tiering"
    status = "Enabled"

    filter {}

    transition {
      days          = var.artifact_ia_transition_days
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = max(var.artifact_object_lock_retention_days, 400)
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/${local.artifacts_bucket}/"
}

data "aws_iam_policy_document" "artifacts" {
  source_policy_documents = [
    data.aws_iam_policy_document.deny_insecure["artifacts"].json,
    data.aws_iam_policy_document.require_kms["artifacts"].json,
  ]
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

#------------------------------------------------------------------------------
# Cross-region replica of the firmware artifacts
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "replica_key" {
  count = var.enable_replication ? 1 : 0

  statement {
    sid       = "EnableIamPolicies"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${var.partition}:iam::${var.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  description             = "IronMesh firmware artifacts replica bucket (${var.replica_region})"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.replica_key[0].json

  tags = {
    Name = "${var.name_prefix}-s3-replica"
  }
}

resource "aws_kms_alias" "replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  name          = "alias/${var.name_prefix}-s3-replica"
  target_key_id = aws_kms_key.replica[0].key_id
}

resource "aws_s3_bucket" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket              = local.replica_bucket
  object_lock_enabled = true

  tags = {
    Name = local.replica_bucket
  }
}

resource "aws_s3_bucket_versioning" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica[0].arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.artifact_object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts_replica]
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id

  rule {
    id     = "firmware-tiering"
    status = "Enabled"

    filter {}

    transition {
      days          = var.artifact_ia_transition_days
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = max(var.artifact_object_lock_retention_days, 400)
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts_replica]
}

data "aws_iam_policy_document" "replica_bucket" {
  count = var.enable_replication ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:${var.partition}:s3:::${local.replica_bucket}", "arn:${var.partition}:s3:::${local.replica_bucket}/*"]

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

resource "aws_s3_bucket_policy" "artifacts_replica" {
  count    = var.enable_replication ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.artifacts_replica[0].id
  policy = data.aws_iam_policy_document.replica_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.artifacts_replica]
}

data "aws_iam_policy_document" "replication_assume" {
  count = var.enable_replication ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "replication" {
  count = var.enable_replication ? 1 : 0

  statement {
    sid       = "ReadSourceBucket"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid = "ReadSourceObjects"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention",
      "s3:GetObjectLegalHold",
    ]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "WriteReplica"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"]
    resources = ["${aws_s3_bucket.artifacts_replica[0].arn}/*"]
  }

  statement {
    sid       = "DecryptSource"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.artifacts.arn}/*"]
    }
  }

  statement {
    sid       = "EncryptReplica"
    actions   = ["kms:Encrypt"]
    resources = [aws_kms_key.replica[0].arn]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.${var.replica_region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.artifacts_replica[0].arn}/*"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = var.enable_replication ? 1 : 0

  name               = var.replication_role_name
  assume_role_policy = data.aws_iam_policy_document.replication_assume[0].json
}

resource "aws_iam_role_policy" "replication" {
  count = var.enable_replication ? 1 : 0

  name   = "firmware-replication"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "artifacts" {
  count = var.enable_replication ? 1 : 0

  bucket = aws_s3_bucket.artifacts.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id       = "replicate-all-firmware"
    status   = "Enabled"
    priority = 1

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.artifacts_replica[0].arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica[0].arn
      }

      replication_time {
        status = "Enabled"

        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"

        event_threshold {
          minutes = 15
        }
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.artifacts,
    aws_s3_bucket_versioning.artifacts_replica,
    aws_iam_role_policy.replication,
  ]
}

#------------------------------------------------------------------------------
# Backups (database dumps, PKI exports)
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "backups" {
  bucket              = local.backups_bucket
  object_lock_enabled = true

  tags = {
    Name = local.backups_bucket
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.backup_object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "backup-tiering-and-expiry"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.backup_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

resource "aws_s3_bucket_logging" "backups" {
  bucket        = aws_s3_bucket.backups.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/${local.backups_bucket}/"
}

data "aws_iam_policy_document" "backups" {
  source_policy_documents = [
    data.aws_iam_policy_document.deny_insecure["backups"].json,
    data.aws_iam_policy_document.require_kms["backups"].json,
  ]
}

resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id
  policy = data.aws_iam_policy_document.backups.json

  depends_on = [aws_s3_bucket_public_access_block.backups]
}

#------------------------------------------------------------------------------
# Access logs (ALB access logs require SSE-S3; S3 server access logs land here too)
#------------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket = local.logs_bucket

  tags = {
    Name = local.logs_bucket
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [data.aws_iam_policy_document.deny_insecure["logs"].json]

  # Regions created before August 2022 deliver ALB logs from a regional ELB account;
  # newer regions use the log delivery service principal. Both are allowed.
  statement {
    sid       = "AllowAlbLogDeliveryAccount"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }

  statement {
    sid       = "AllowAlbLogDeliveryService"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowS3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/s3/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}
