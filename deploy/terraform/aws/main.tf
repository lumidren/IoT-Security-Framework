#------------------------------------------------------------------------------
# IronMesh AWS platform
#
# Apply order (see README):
#   1. terraform apply -target=module.kms -target=module.network
#   2. terraform apply -target=module.eks
#   3. terraform apply                      (everything else, incl. Helm add-ons)
#------------------------------------------------------------------------------

module "kms" {
  source = "./modules/kms"

  name_prefix             = local.name_prefix
  region                  = var.region
  account_id              = local.account_id
  partition               = local.partition
  deletion_window_in_days = var.kms_deletion_window_days
  admin_principal_arns    = local.kms_admin_principal_arns
  ceremony_role_arn       = local.ceremony_role_arn
  root_ca_require_mfa     = var.root_ca_require_mfa
  create_factory_ca_key   = var.create_factory_ca_key
  create_msk_key          = local.msk_provisioned
  pki_role_arn            = local.irsa_role_arns["pki"]
  ota_role_arn            = local.irsa_role_arns["ota"]
  backup_role_arn         = local.irsa_role_arns["backup"]
  eks_cluster_role_arn    = local.eks_cluster_role_arn
  eks_node_role_arn       = local.eks_node_role_arn
  ebs_csi_role_arn        = local.ebs_csi_role_arn
  s3_replication_role_arn = local.s3_replication_role_arn
  secrets_path_prefix     = local.secrets_path_prefix
}

module "network" {
  source = "./modules/network"

  name_prefix             = local.name_prefix
  vpc_cidr                = var.vpc_cidr
  az_count                = var.az_count
  cluster_name            = local.cluster_name
  single_nat_gateway      = var.single_nat_gateway
  interface_endpoints     = var.vpc_interface_endpoints
  flow_log_retention_days = var.log_retention_days
  flow_log_kms_key_arn    = module.kms.key_arns["logs"]
}

module "eks" {
  source = "./modules/eks"

  cluster_name                 = local.cluster_name
  cluster_version              = var.eks_version
  cluster_role_name            = local.eks_cluster_role_name
  node_role_name               = local.eks_node_role_name
  ebs_csi_role_name            = local.ebs_csi_role_name
  subnet_ids                   = module.network.private_subnet_ids
  endpoint_public_access       = var.cluster_endpoint_public_access
  endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  secrets_kms_key_arn          = module.kms.key_arns["eks"]
  ebs_kms_key_arn              = module.kms.key_arns["eks"]
  logs_kms_key_arn             = module.kms.key_arns["logs"]
  log_retention_days           = var.log_retention_days
  node_groups                  = var.node_groups
  admin_principal_arns         = var.cluster_admin_principal_arns
  enable_container_insights    = var.enable_container_insights
  partition                    = local.partition
  tags                         = local.tags
}

module "eks_addons" {
  source = "./modules/eks-addons"

  name_prefix       = local.name_prefix
  cluster_name      = module.eks.cluster_name
  region            = var.region
  vpc_id            = module.network.vpc_id
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_provider_url = module.eks.oidc_provider_url
  dns_zone_id       = data.aws_route53_zone.this.zone_id
  domain_filter     = var.domain
  chart_versions    = var.helm_chart_versions
  partition         = local.partition

  depends_on = [module.eks]
}

module "msk" {
  source = "./modules/msk"
  count  = local.use_msk ? 1 : 0

  name_prefix               = local.name_prefix
  mode                      = var.kafka_mode
  vpc_id                    = module.network.vpc_id
  subnet_ids                = module.network.isolated_subnet_ids
  client_security_group_ids = [module.eks.cluster_security_group_id]
  kms_key_arn               = lookup(module.kms.key_arns, "msk", null)
  logs_kms_key_arn          = module.kms.key_arns["logs"]
  log_retention_days        = var.log_retention_days
  kafka_version             = var.msk_kafka_version
  broker_instance_type      = var.msk_broker_instance_type
  broker_count              = var.msk_broker_count
  ebs_volume_size_gb        = var.msk_ebs_volume_size_gb
}

module "rds" {
  source = "./modules/rds"

  name_prefix                         = local.name_prefix
  vpc_id                              = module.network.vpc_id
  subnet_ids                          = module.network.isolated_subnet_ids
  client_security_group_ids           = [module.eks.cluster_security_group_id]
  kms_key_arn                         = module.kms.key_arns["rds"]
  logs_kms_key_arn                    = module.kms.key_arns["logs"]
  log_retention_days                  = var.log_retention_days
  instance_class                      = var.rds_instance_class
  engine_version                      = var.rds_engine_version
  multi_az                            = var.rds_multi_az
  allocated_storage_gb                = var.rds_allocated_storage_gb
  max_allocated_storage_gb            = var.rds_max_allocated_storage_gb
  backup_retention_days               = var.rds_backup_retention_days
  performance_insights_retention_days = var.rds_performance_insights_retention_days
  deletion_protection                 = var.rds_deletion_protection
}

module "s3" {
  source = "./modules/s3"

  providers = {
    aws = aws
    aws.replica = aws.replica
  }

  name_prefix                         = local.name_prefix
  account_id                          = local.account_id
  region                              = var.region
  replica_region                      = var.replica_region
  partition                           = local.partition
  kms_key_arn                         = module.kms.key_arns["s3"]
  enable_replication                  = var.enable_artifact_replication
  replication_role_name               = local.s3_replication_role_name
  artifact_object_lock_retention_days = var.artifact_object_lock_retention_days
  artifact_ia_transition_days         = var.artifact_ia_transition_days
  backup_retention_days               = var.backup_retention_days
  backup_object_lock_retention_days   = var.backup_object_lock_retention_days
  kms_deletion_window_in_days         = var.kms_deletion_window_days
}

module "alb" {
  source = "./modules/alb"

  name_prefix               = local.name_prefix
  vpc_id                    = module.network.vpc_id
  vpc_cidr                  = module.network.vpc_cidr
  public_subnet_ids         = module.network.public_subnet_ids
  domain                    = var.domain
  hosts                     = local.hosts
  dns_zone_id               = data.aws_route53_zone.this.zone_id
  cluster_security_group_id = module.eks.cluster_security_group_id
  access_logs_enabled       = var.alb_access_logs_enabled
  access_logs_bucket_name   = module.s3.logs_bucket_name
  waf_rate_limit            = var.waf_rate_limit
  log_retention_days        = var.log_retention_days
  logs_kms_key_arn          = module.kms.key_arns["logs"]
}

module "observability" {
  source = "./modules/observability"

  name_prefix                      = local.name_prefix
  region                           = var.region
  alarm_email_endpoints            = var.alarm_email_endpoints
  alerts_kms_key_arn               = module.kms.key_arns["alerts"]
  log_retention_days               = var.log_retention_days
  logs_kms_key_arn                 = module.kms.key_arns["logs"]
  rds_instance_identifier          = module.rds.identifier
  rds_free_storage_threshold_bytes = var.rds_free_storage_alarm_gb * 1024 * 1024 * 1024
  msk_cluster_name                 = local.msk_provisioned ? one(module.msk[*].cluster_name) : null
  alb_arn_suffix                   = module.alb.alb_arn_suffix
  alb_target_group_arn_suffixes    = module.alb.alb_target_group_arn_suffixes
  nlb_arn_suffix                   = module.alb.nlb_arn_suffix
  nlb_target_group_arn_suffixes    = module.alb.nlb_target_group_arn_suffixes
  waf_web_acl_name                 = module.alb.waf_web_acl_name
  eks_cluster_name                 = module.eks.cluster_name
  enable_container_insights        = var.enable_container_insights
}

module "iam" {
  source = "./modules/iam"

  account_id                       = local.account_id
  partition                        = local.partition
  region                           = var.region
  oidc_provider_arn                = module.eks.oidc_provider_arn
  oidc_provider_url                = module.eks.oidc_provider_url
  namespace                        = var.kubernetes_namespace
  service_account_names            = local.service_account_names
  role_names                       = local.irsa_role_names
  external_secrets_role_name       = local.external_secrets_role_name
  external_secrets_namespace       = var.external_secrets_namespace
  external_secrets_service_account = var.external_secrets_service_account
  secrets_path_prefix              = local.secrets_path_prefix
  ceremony_role_name               = local.ceremony_role_name
  ceremony_principal_arns          = local.ceremony_principal_arns
  ceremony_require_mfa             = var.root_ca_require_mfa
  kms_key_arns                     = module.kms.key_arns
  firmware_signing_secret_arn      = module.kms.firmware_signing_secret_arn
  artifacts_bucket_arn             = module.s3.artifacts_bucket_arn
  artifacts_replica_bucket_arn     = module.s3.artifacts_replica_bucket_arn
  backups_bucket_arn               = module.s3.backups_bucket_arn
  rds_resource_id                  = module.rds.resource_id
  db_users                         = local.db_users
  kafka_mode                       = var.kafka_mode
  msk_cluster_arn                  = one(module.msk[*].cluster_arn)
}
