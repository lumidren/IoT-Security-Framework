data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_route53_zone" "this" {
  name         = var.dns_zone_name
  private_zone = false
}

locals {
  name_prefix  = "${var.name_prefix}-${var.environment}"
  cluster_name = "${local.name_prefix}-eks"
  account_id   = data.aws_caller_identity.current.account_id
  partition    = data.aws_partition.current.partition

  tags = merge(
    {
      Project     = "IronMesh"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.tags,
  )

  # The identity running Terraform always keeps KMS administrative rights so that no key can
  # become unmanageable. STS assumed-role ARNs are normalised to the underlying IAM role ARN.
  caller_arn       = data.aws_caller_identity.current.arn
  caller_arn_parts = split("/", local.caller_arn)
  caller_principal_arn = (
    length(regexall(":assumed-role/", local.caller_arn)) > 0
    ? "arn:${local.partition}:iam::${local.account_id}:role/${local.caller_arn_parts[1]}"
    : local.caller_arn
  )

  kms_admin_principal_arns = distinct(concat([local.caller_principal_arn], var.kms_admin_principal_arns))
  ceremony_principal_arns  = length(var.ceremony_principal_arns) > 0 ? var.ceremony_principal_arns : [local.caller_principal_arn]

  # Role names are fixed up-front so that KMS key policies (module.kms) can reference the
  # roles before module.iam creates them, without a dependency cycle. Key policies use the
  # account principal with an aws:PrincipalArn condition, which KMS does not validate for
  # existence at creation time.
  irsa_services         = ["pki", "policy", "bridge", "registry", "ota", "anomaly", "backup"]
  irsa_role_names       = { for s in local.irsa_services : s => "${local.name_prefix}-irsa-${s}" }
  irsa_role_arns        = { for s, n in local.irsa_role_names : s => "arn:${local.partition}:iam::${local.account_id}:role/${n}" }
  service_account_names = { for s in local.irsa_services : s => "${var.irsa_service_account_prefix}-${s}" }

  external_secrets_role_name = "${local.name_prefix}-irsa-external-secrets"
  external_secrets_role_arn  = "arn:${local.partition}:iam::${local.account_id}:role/${local.external_secrets_role_name}"
  ceremony_role_name         = "${local.name_prefix}-ca-ceremony"
  ceremony_role_arn          = "arn:${local.partition}:iam::${local.account_id}:role/${local.ceremony_role_name}"
  eks_cluster_role_name      = "${local.cluster_name}-cluster"
  eks_cluster_role_arn       = "arn:${local.partition}:iam::${local.account_id}:role/${local.eks_cluster_role_name}"
  eks_node_role_name         = "${local.cluster_name}-node"
  eks_node_role_arn          = "arn:${local.partition}:iam::${local.account_id}:role/${local.eks_node_role_name}"
  ebs_csi_role_name          = "${local.cluster_name}-ebs-csi"
  ebs_csi_role_arn           = "arn:${local.partition}:iam::${local.account_id}:role/${local.ebs_csi_role_name}"
  s3_replication_role_name   = "${local.name_prefix}-s3-replication"
  s3_replication_role_arn    = "arn:${local.partition}:iam::${local.account_id}:role/${local.s3_replication_role_name}"

  use_msk         = var.kafka_mode != "redpanda"
  msk_provisioned = var.kafka_mode == "msk-provisioned"

  hosts = {
    console  = "console.${var.domain}"
    registry = "registry.${var.domain}"
    ota      = "ota.${var.domain}"
    pki      = "pki.${var.domain}"
    mqtt     = "mqtt.${var.domain}"
  }

  # Database roles used by the services (non-owner, RLS enforced; see DESIGN_CONTRACT.md §8)
  # and by the backup job. RDS IAM authentication maps these to rds-db:connect grants.
  db_users = {
    pki      = "pki_app"
    registry = "registry_app"
    ota      = "ota_app"
    anomaly  = "anomaly_app"
    backup   = "ironmesh_backup"
  }

  secrets_path_prefix = "ironmesh/${var.environment}/"
}
