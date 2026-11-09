#------------------------------------------------------------------------------
# Key inventory
#
# Asymmetric signing keys (CA hierarchy, DESIGN_CONTRACT.md §2):
#   root_ca        ECC_NIST_P384  usable only by the ceremony role (MFA)        -> "offline" root
#   factory_ca     ECC_NIST_P384  bootstrap certificates (10 y)                  (optional)
#   device_ca      ECC_NIST_P256  operational device certificates (14 d)
#   services_ca    ECC_NIST_P256  broker / EST / API server certificates (90 d)
#
# PKI bundle signing (X-IronMesh-Bundle, COSE_Sign1 EdDSA, kid "pki-bundle"): the PKI signs
# with Ed25519 (services/pki/internal/est/bundle.go), which KMS cannot hold either, so the
# seed follows the firmware-key pattern below: Secrets Manager secret
# `<prefix>pki/bundle-signing-key` encrypted under the symmetric CMK `bundle_kek`, decryptable
# only by the pki workload identity (and the ceremony role) through Secrets Manager.
#
# Firmware signing: the contract mandates Ed25519 (COSE alg -8) plus optional ML-DSA-65.
# AWS KMS asymmetric keys do not support Ed25519 (only RSA, ECC NIST P-256/384/521,
# secp256k1, SM2), so the Ed25519 private key is generated in a ceremony and stored in
# Secrets Manager encrypted under the symmetric CMK `firmware_kek`. Only the ota service
# (runtime signing, key held in memory only) and the ceremony role can decrypt it, and
# every use is a CloudTrail `kms:Decrypt` + `secretsmanager:GetSecretValue` event.
# Signing-key rotation is done by adding a new key to the bundle's `fw_signing_pubkeys`
# list and re-wrapping; KEK rotation is automatic (yearly) and transparent.
#
# Symmetric data keys: eks (secrets + EBS), rds, s3, logs, alerts, msk (provisioned only).
#------------------------------------------------------------------------------

locals {
  account_root = "arn:${var.partition}:iam::${var.account_id}:root"

  ca_keys = merge(
    {
      root_ca = {
        spec        = "ECC_NIST_P384"
        description = "IronMesh Root CA signing key (ceremony role only, MFA)"
      }
      device_ca = {
        spec        = "ECC_NIST_P256"
        description = "IronMesh Device CA signing key (operational device certificates)"
      }
      services_ca = {
        spec        = "ECC_NIST_P256"
        description = "IronMesh Services CA signing key (broker/EST/API server certificates)"
      }
    },
    var.create_factory_ca_key ? {
      factory_ca = {
        spec        = "ECC_NIST_P384"
        description = "IronMesh Factory CA signing key (bootstrap certificates)"
      }
    } : {},
  )

  symmetric_keys = merge(
    {
      firmware_kek = "IronMesh firmware signing KEK (wraps the Ed25519/ML-DSA signing keys in Secrets Manager)"
      bundle_kek   = "IronMesh PKI bundle KEK (wraps the Ed25519 X-IronMesh-Bundle signing seed in Secrets Manager)"
      eks          = "IronMesh EKS secrets envelope encryption and node EBS volumes"
      rds          = "IronMesh RDS storage, Performance Insights and master credentials"
      s3           = "IronMesh S3 firmware artifacts and backups"
      logs         = "IronMesh CloudWatch Logs"
      alerts       = "IronMesh SNS alerts topic"
    },
    var.create_msk_key ? { msk = "IronMesh MSK at-rest encryption" } : {},
  )

  # Administrative actions only: no Sign/Verify/Encrypt/Decrypt/GenerateDataKey and no
  # CreateGrant, so administrators cannot delegate signing to themselves silently.
  admin_actions = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:GetPublicKey",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListKeyPolicies",
    "kms:ListKeyRotations",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:RotateKeyOnDemand",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
  ]

  usage_actions = [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:DescribeKey",
  ]

  ca_policies = {
    for k in keys(local.ca_keys) :
    k => (k == "root_ca" ? data.aws_iam_policy_document.root_ca.json : data.aws_iam_policy_document.ca_signing.json)
  }

  symmetric_policies = {
    firmware_kek = data.aws_iam_policy_document.firmware_kek.json
    bundle_kek   = data.aws_iam_policy_document.bundle_kek.json
    eks          = data.aws_iam_policy_document.eks.json
    rds          = data.aws_iam_policy_document.data_generic.json
    s3           = data.aws_iam_policy_document.s3.json
    logs         = data.aws_iam_policy_document.logs.json
    alerts       = data.aws_iam_policy_document.alerts.json
    msk          = data.aws_iam_policy_document.data_generic.json
  }
}

#------------------------------------------------------------------------------
# Policy building blocks
#------------------------------------------------------------------------------

# Administration by named principals only. KMS does not validate aws:PrincipalArn values, so
# roles created later (module.iam) can be referenced without a dependency cycle.
data "aws_iam_policy_document" "admin" {
  statement {
    sid       = "KeyAdministration"
    actions   = local.admin_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arns
    }
  }
}

# Public-key material is not sensitive: any principal in the account may fetch/verify.
data "aws_iam_policy_document" "verify" {
  statement {
    sid       = "AllowVerifyInAccount"
    actions   = ["kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_iam_policy_document" "ca_signing" {
  source_policy_documents = [
    data.aws_iam_policy_document.admin.json,
    data.aws_iam_policy_document.verify.json,
  ]

  statement {
    sid       = "AllowSigningByPkiService"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.pki_role_arn, var.ceremony_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_256", "ECDSA_SHA_384"]
    }
  }
}

data "aws_iam_policy_document" "root_ca" {
  source_policy_documents = [
    data.aws_iam_policy_document.admin.json,
    data.aws_iam_policy_document.verify.json,
  ]

  statement {
    sid       = "AllowSigningByCeremonyRoleOnly"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ceremony_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_384"]
    }

    dynamic "condition" {
      for_each = var.root_ca_require_mfa ? [1] : []

      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

data "aws_iam_policy_document" "firmware_kek" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  # The ota service may only unwrap through Secrets Manager (no direct Decrypt API use).
  statement {
    sid       = "AllowOtaUnwrapViaSecretsManager"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ota_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowCeremonyWrapViaSecretsManager"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ceremony_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

# The pki service may only unwrap the bundle seed through Secrets Manager (no direct Decrypt).
data "aws_iam_policy_document" "bundle_kek" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowPkiUnwrapViaSecretsManager"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.pki_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowCeremonyWrapViaSecretsManager"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ceremony_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

# Generic data key: administration by admins, usage delegated to IAM policies in this account
# (RDS/MSK create grants on behalf of the deployer).
data "aws_iam_policy_document" "data_generic" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowUseThroughIamPoliciesInAccount"
    actions   = concat(local.usage_actions, ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"])
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_iam_policy_document" "eks" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowEksControlPlaneSecretsEncryption"
    actions   = concat(local.usage_actions, ["kms:CreateGrant", "kms:ListGrants"])
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.eks_cluster_role_arn]
    }
  }

  statement {
    sid       = "AllowEbsVolumeEncryption"
    actions   = local.usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values = [
        var.eks_node_role_arn,
        var.ebs_csi_role_arn,
        "arn:${var.partition}:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
      ]
    }
  }

  statement {
    sid       = "AllowEbsGrants"
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values = [
        var.eks_node_role_arn,
        var.ebs_csi_role_arn,
        "arn:${var.partition}:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
      ]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  # The deployer needs usage rights for the EKS encryption_config validation at create time.
  statement {
    sid       = "AllowDeployerUse"
    actions   = local.usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arns
    }
  }
}

data "aws_iam_policy_document" "s3" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowServiceRolesViaS3"
    actions   = local.usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ota_role_arn, var.backup_role_arn, var.s3_replication_role_arn, var.ceremony_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowDeployerUse"
    actions   = local.usage_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arns
    }
  }
}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowCloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:*"]
    }
  }
}

data "aws_iam_policy_document" "alerts" {
  source_policy_documents = [data.aws_iam_policy_document.admin.json]

  statement {
    sid       = "AllowCloudWatchAlarmsToPublish"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }

  statement {
    sid       = "AllowSnsSubscribersInAccount"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sns.${var.region}.amazonaws.com"]
    }
  }
}

#------------------------------------------------------------------------------
# Keys and aliases
#------------------------------------------------------------------------------

resource "aws_kms_key" "ca" {
  for_each = local.ca_keys

  description              = each.value.description
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = each.value.spec
  deletion_window_in_days  = var.deletion_window_in_days
  policy                   = local.ca_policies[each.key]

  tags = {
    Name    = "${var.name_prefix}-${replace(each.key, "_", "-")}"
    Purpose = each.key
  }
}

resource "aws_kms_alias" "ca" {
  for_each = local.ca_keys

  name          = "alias/${var.name_prefix}-${replace(each.key, "_", "-")}"
  target_key_id = aws_kms_key.ca[each.key].key_id
}

resource "aws_kms_key" "symmetric" {
  for_each = local.symmetric_keys

  description             = each.value
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  rotation_period_in_days = 365
  policy                  = local.symmetric_policies[each.key]

  tags = {
    Name    = "${var.name_prefix}-${replace(each.key, "_", "-")}"
    Purpose = each.key
  }
}

resource "aws_kms_alias" "symmetric" {
  for_each = local.symmetric_keys

  name          = "alias/${var.name_prefix}-${replace(each.key, "_", "-")}"
  target_key_id = aws_kms_key.symmetric[each.key].key_id
}

#------------------------------------------------------------------------------
# Firmware signing key container (value populated by the ceremony, never by Terraform)
#------------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "firmware_signing_key" {
  name                    = "${var.secrets_path_prefix}ota/firmware-signing-key"
  description             = "Ed25519 (and optional ML-DSA-65) firmware signing private keys, wrapped by ${aws_kms_alias.symmetric["firmware_kek"].name}. Written by the ceremony role only."
  kms_key_id              = aws_kms_key.symmetric["firmware_kek"].arn
  recovery_window_in_days = 30

  tags = {
    Name = "${var.name_prefix}-firmware-signing-key"
  }
}

data "aws_iam_policy_document" "firmware_signing_key" {
  # Read access is limited to the ota service and the ceremony role; everyone else,
  # including administrators and the External Secrets Operator, is explicitly denied.
  statement {
    sid       = "DenyReadToEveryoneElse"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ota_role_arn, var.ceremony_role_arn]
    }
  }

  statement {
    sid       = "DenyWriteToEveryoneButCeremony"
    effect    = "Deny"
    actions   = ["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:RestoreSecret"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ceremony_role_arn]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "firmware_signing_key" {
  secret_arn = aws_secretsmanager_secret.firmware_signing_key.arn
  policy     = data.aws_iam_policy_document.firmware_signing_key.json
}

#------------------------------------------------------------------------------
# PKI bundle signing key container (Ed25519 seed for X-IronMesh-Bundle, COSE alg -8, kid
# "pki-bundle"). Populated by the ceremony, never by Terraform; readable only by the pki
# workload identity and the ceremony role, unwrapped through Secrets Manager.
#------------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "bundle_signing_key" {
  name                    = "${var.secrets_path_prefix}pki/bundle-signing-key"
  description             = "Ed25519 PKI bundle signing seed, wrapped by ${aws_kms_alias.symmetric["bundle_kek"].name}. Written by the ceremony role only."
  kms_key_id              = aws_kms_key.symmetric["bundle_kek"].arn
  recovery_window_in_days = 30

  tags = {
    Name = "${var.name_prefix}-bundle-signing-key"
  }
}

data "aws_iam_policy_document" "bundle_signing_key" {
  statement {
    sid       = "DenyReadToEveryoneElse"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.pki_role_arn, var.ceremony_role_arn]
    }
  }

  statement {
    sid       = "DenyWriteToEveryoneButCeremony"
    effect    = "Deny"
    actions   = ["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:RestoreSecret"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.ceremony_role_arn]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "bundle_signing_key" {
  secret_arn = aws_secretsmanager_secret.bundle_signing_key.arn
  policy     = data.aws_iam_policy_document.bundle_signing_key.json
}
