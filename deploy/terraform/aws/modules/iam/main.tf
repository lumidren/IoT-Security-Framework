#------------------------------------------------------------------------------
# IRSA roles: one per service, least privilege
#
#   pki       sign with Device/Services/Bundle/(Factory) CA keys, never the root; RDS pki db
#   policy    Kafka write im.auth/im.audit (MSK only)
#   bridge    Kafka create topics + write im.ingest/im.auth/im.audit (MSK only)
#   registry  RDS registry db; Kafka read ingest/auth/alerts/audit, write audit/commands
#   ota       RDS ota db; S3 artifacts; unwrap firmware signing key via Secrets Manager
#   anomaly   RDS anomaly db; Kafka read ingest/auth/commands, write alerts/audit
#   backup    S3 backups write, artifacts read, KMS metadata, RDS backup user
#   external-secrets  read ironmesh/<env>/* secrets, explicitly denied the firmware key
#   ca-ceremony (human, MFA)  root CA signing, firmware key wrapping
#------------------------------------------------------------------------------

locals {
  use_msk          = var.kafka_mode != "redpanda" && var.msk_cluster_arn != null
  topic_arn_prefix = local.use_msk ? replace(var.msk_cluster_arn, ":cluster/", ":topic/") : ""
  group_arn_prefix = local.use_msk ? replace(var.msk_cluster_arn, ":cluster/", ":group/") : ""

  # Event bus topics (DESIGN_CONTRACT.md §7 + API_CONTRACT.md §6).
  topics     = ["im.ingest", "im.auth", "im.alerts", "im.audit", "im.commands"]
  topic_arns = { for t in local.topics : t => "${local.topic_arn_prefix}/${t}" }

  kafka_access = {
    bridge = {
      read   = []
      write  = ["im.ingest", "im.auth", "im.audit"]
      create = local.topics
      groups = []
    }
    policy = {
      read   = []
      write  = ["im.auth", "im.audit"]
      create = []
      groups = []
    }
    registry = {
      read   = ["im.ingest", "im.auth", "im.alerts", "im.audit"]
      write  = ["im.audit", "im.commands"]
      create = []
      groups = ["registry-*"]
    }
    ota = {
      read   = ["im.ingest", "im.commands"]
      write  = ["im.audit"]
      create = []
      groups = ["ota-*"]
    }
    anomaly = {
      read   = ["im.ingest", "im.auth", "im.commands"]
      write  = ["im.alerts", "im.audit"]
      create = []
      groups = ["anomaly-*"]
    }
  }

  rds_connect_arns = {
    for svc, user in var.db_users :
    svc => "arn:${var.partition}:rds-db:${var.region}:${var.account_id}:dbuser:${var.rds_resource_id}/${user}"
  }

  secrets_arn_prefix = "arn:${var.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${var.secrets_path_prefix}"

  signing_key_purposes = ["device_ca", "services_ca", "bundle_signing", "factory_ca"]
  pki_signing_key_arns = [for k in local.signing_key_purposes : var.kms_key_arns[k] if contains(keys(var.kms_key_arns), k)]
  all_ca_key_arns      = [for k in concat(["root_ca"], local.signing_key_purposes) : var.kms_key_arns[k] if contains(keys(var.kms_key_arns), k)]

  artifact_bucket_arns = compact([var.artifacts_bucket_arn, var.artifacts_replica_bucket_arn == null ? "" : var.artifacts_replica_bucket_arn])
}

#------------------------------------------------------------------------------
# Trust policies
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "irsa_assume" {
  for_each = var.role_names

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account_names[each.key]}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa" {
  for_each = var.role_names

  name                 = each.value
  assume_role_policy   = data.aws_iam_policy_document.irsa_assume[each.key].json
  max_session_duration = 3600

  tags = {
    Name            = each.value
    IronMeshService = each.key
  }
}

#------------------------------------------------------------------------------
# Kafka (MSK IAM) statements per service
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "kafka" {
  for_each = local.use_msk ? local.kafka_access : {}

  statement {
    sid       = "KafkaConnect"
    actions   = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster", "kafka-cluster:DescribeClusterDynamicConfiguration"]
    resources = [var.msk_cluster_arn]
  }

  dynamic "statement" {
    for_each = length(each.value.read) > 0 ? [1] : []

    content {
      sid       = "KafkaRead"
      actions   = ["kafka-cluster:DescribeTopic", "kafka-cluster:DescribeTopicDynamicConfiguration", "kafka-cluster:ReadData"]
      resources = [for t in each.value.read : local.topic_arns[t]]
    }
  }

  dynamic "statement" {
    for_each = length(each.value.write) > 0 ? [1] : []

    content {
      sid       = "KafkaWrite"
      actions   = ["kafka-cluster:DescribeTopic", "kafka-cluster:WriteData", "kafka-cluster:WriteDataIdempotently"]
      resources = [for t in each.value.write : local.topic_arns[t]]
    }
  }

  dynamic "statement" {
    for_each = length(each.value.create) > 0 ? [1] : []

    content {
      sid       = "KafkaCreateTopics"
      actions   = ["kafka-cluster:CreateTopic", "kafka-cluster:DescribeTopic"]
      resources = [for t in each.value.create : local.topic_arns[t]]
    }
  }

  dynamic "statement" {
    for_each = length(each.value.groups) > 0 ? [1] : []

    content {
      sid       = "KafkaConsumerGroups"
      actions   = ["kafka-cluster:AlterGroup", "kafka-cluster:DescribeGroup"]
      resources = [for g in each.value.groups : "${local.group_arn_prefix}/${g}"]
    }
  }
}

#------------------------------------------------------------------------------
# pki
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "pki" {
  statement {
    sid       = "SignWithOnlineCaKeys"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = local.pki_signing_key_arns
  }

  statement {
    sid       = "ReadCaPublicKeys"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey", "kms:Verify"]
    resources = local.all_ca_key_arns
  }

  statement {
    sid       = "ConnectPkiDatabase"
    actions   = ["rds-db:connect"]
    resources = [local.rds_connect_arns["pki"]]
  }
}

resource "aws_iam_role_policy" "pki" {
  name   = "pki"
  role   = aws_iam_role.irsa["pki"].id
  policy = data.aws_iam_policy_document.pki.json
}

#------------------------------------------------------------------------------
# policy / bridge (Kafka only, MSK mode)
#------------------------------------------------------------------------------

resource "aws_iam_role_policy" "policy_kafka" {
  count = local.use_msk ? 1 : 0

  name   = "kafka"
  role   = aws_iam_role.irsa["policy"].id
  policy = data.aws_iam_policy_document.kafka["policy"].json
}

resource "aws_iam_role_policy" "bridge_kafka" {
  count = local.use_msk ? 1 : 0

  name   = "kafka"
  role   = aws_iam_role.irsa["bridge"].id
  policy = data.aws_iam_policy_document.kafka["bridge"].json
}

#------------------------------------------------------------------------------
# registry
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "registry" {
  source_policy_documents = local.use_msk ? [data.aws_iam_policy_document.kafka["registry"].json] : []

  statement {
    sid       = "ConnectRegistryDatabase"
    actions   = ["rds-db:connect"]
    resources = [local.rds_connect_arns["registry"]]
  }
}

resource "aws_iam_role_policy" "registry" {
  name   = "registry"
  role   = aws_iam_role.irsa["registry"].id
  policy = data.aws_iam_policy_document.registry.json
}

#------------------------------------------------------------------------------
# ota
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "ota" {
  source_policy_documents = local.use_msk ? [data.aws_iam_policy_document.kafka["ota"].json] : []

  statement {
    sid       = "ConnectOtaDatabase"
    actions   = ["rds-db:connect"]
    resources = [local.rds_connect_arns["ota"]]
  }

  statement {
    sid       = "ListArtifactsBucket"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
    resources = [var.artifacts_bucket_arn]
  }

  statement {
    sid = "ReadWriteArtifacts"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
    ]
    resources = ["${var.artifacts_bucket_arn}/*"]
  }

  statement {
    sid       = "UseArtifactsKmsKeyThroughS3"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.kms_key_arns["s3"]]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "ReadWrappedFirmwareSigningKey"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [var.firmware_signing_secret_arn]
  }

  statement {
    sid       = "UnwrapFirmwareSigningKeyThroughSecretsManager"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arns["firmware_kek"]]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ota" {
  name   = "ota"
  role   = aws_iam_role.irsa["ota"].id
  policy = data.aws_iam_policy_document.ota.json
}

#------------------------------------------------------------------------------
# anomaly
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "anomaly" {
  source_policy_documents = local.use_msk ? [data.aws_iam_policy_document.kafka["anomaly"].json] : []

  statement {
    sid       = "ConnectAnomalyDatabase"
    actions   = ["rds-db:connect"]
    resources = [local.rds_connect_arns["anomaly"]]
  }
}

resource "aws_iam_role_policy" "anomaly" {
  name   = "anomaly"
  role   = aws_iam_role.irsa["anomaly"].id
  policy = data.aws_iam_policy_document.anomaly.json
}

#------------------------------------------------------------------------------
# backup (scripts/backup/*.sh)
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "backup" {
  statement {
    sid       = "ListBuckets"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketReplication", "s3:GetBucketObjectLockConfiguration"]
    resources = concat([var.backups_bucket_arn], local.artifact_bucket_arns)
  }

  statement {
    sid       = "WriteBackups"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:GetObjectRetention"]
    resources = ["${var.backups_bucket_arn}/*"]
  }

  statement {
    sid       = "ReadArtifactsForVerification"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectRetention"]
    resources = [for b in local.artifact_bucket_arns : "${b}/*"]
  }

  statement {
    sid       = "UseS3KmsKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.kms_key_arns["s3"]]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "ReadKeyMetadata"
    actions   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListResourceTags"]
    resources = values(var.kms_key_arns)
  }

  statement {
    sid       = "ListAliases"
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }

  statement {
    sid       = "ConnectAsBackupUser"
    actions   = ["rds-db:connect"]
    resources = [local.rds_connect_arns["backup"]]
  }

  statement {
    sid       = "DescribeDatabases"
    actions   = ["rds:DescribeDBInstances", "rds:DescribeDBSnapshots"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadQuorumInventory"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = ["${local.secrets_arn_prefix}pki/root-ca-quorum-inventory*"]
  }

  statement {
    sid       = "DescribeFirmwareSecretReplication"
    actions   = ["secretsmanager:DescribeSecret"]
    resources = [var.firmware_signing_secret_arn]
  }
}

resource "aws_iam_role_policy" "backup" {
  name   = "backup"
  role   = aws_iam_role.irsa["backup"].id
  policy = data.aws_iam_policy_document.backup.json
}

#------------------------------------------------------------------------------
# External Secrets Operator
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "external_secrets_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.external_secrets_namespace}:${var.external_secrets_service_account}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "external_secrets" {
  statement {
    sid       = "ReadIronMeshSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds", "secretsmanager:GetResourcePolicy"]
    resources = ["${local.secrets_arn_prefix}*"]
  }

  statement {
    sid       = "ListSecrets"
    actions   = ["secretsmanager:ListSecrets", "secretsmanager:BatchGetSecretValue"]
    resources = ["*"]
  }

  # The firmware signing key is consumed directly by the ota service and must never be
  # materialised as a Kubernetes Secret.
  statement {
    sid       = "NeverSyncFirmwareSigningKey"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"]
    resources = [var.firmware_signing_secret_arn]
  }
}

resource "aws_iam_role" "external_secrets" {
  name                 = var.external_secrets_role_name
  assume_role_policy   = data.aws_iam_policy_document.external_secrets_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "external_secrets" {
  name   = "secrets-manager-read"
  role   = aws_iam_role.external_secrets.id
  policy = data.aws_iam_policy_document.external_secrets.json
}

#------------------------------------------------------------------------------
# CA ceremony role (humans, MFA)
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "ceremony_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.ceremony_principal_arns
    }

    dynamic "condition" {
      for_each = var.ceremony_require_mfa ? [1] : []

      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

data "aws_iam_policy_document" "ceremony" {
  statement {
    sid       = "SignWithRootCa"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [var.kms_key_arns["root_ca"]]
  }

  statement {
    sid       = "ReadAllCaPublicKeys"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey", "kms:Verify"]
    resources = local.all_ca_key_arns
  }

  statement {
    sid       = "WrapFirmwareSigningKeyThroughSecretsManager"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.kms_key_arns["firmware_kek"]]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid = "ManageCeremonySecrets"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds",
      "secretsmanager:CreateSecret",
      "secretsmanager:TagResource",
    ]
    resources = [
      var.firmware_signing_secret_arn,
      "${local.secrets_arn_prefix}pki/root-ca-quorum-inventory*",
    ]
  }
}

resource "aws_iam_role" "ceremony" {
  name                 = var.ceremony_role_name
  assume_role_policy   = data.aws_iam_policy_document.ceremony_assume.json
  max_session_duration = 3600

  tags = {
    Name = var.ceremony_role_name
  }
}

resource "aws_iam_role_policy" "ceremony" {
  name   = "ca-ceremony"
  role   = aws_iam_role.ceremony.id
  policy = data.aws_iam_policy_document.ceremony.json
}
