#------------------------------------------------------------------------------
# Cluster access
#------------------------------------------------------------------------------

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS API server endpoint."
  value       = module.eks.cluster_endpoint
}

output "eks_oidc_provider_arn" {
  description = "IAM OIDC provider ARN used for IRSA."
  value       = module.eks.oidc_provider_arn
}

output "kubeconfig_command" {
  description = "Command that writes a kubeconfig entry for the cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

#------------------------------------------------------------------------------
# Network
#------------------------------------------------------------------------------

output "vpc_id" {
  description = "VPC id."
  value       = module.network.vpc_id
}

output "private_subnet_ids" {
  description = "Private (node) subnet ids."
  value       = module.network.private_subnet_ids
}

output "isolated_subnet_ids" {
  description = "Isolated (RDS/MSK) subnet ids."
  value       = module.network.isolated_subnet_ids
}

output "nat_public_ips" {
  description = "NAT gateway EIPs (egress IPs of the services, useful for allow-lists at SIEM/OIDC providers)."
  value       = module.network.nat_public_ips
}

#------------------------------------------------------------------------------
# Data stores
#------------------------------------------------------------------------------

output "rds_endpoint" {
  description = "PostgreSQL endpoint (host:port)."
  value       = "${module.rds.address}:${module.rds.port}"
}

output "rds_master_user_secret_arn" {
  description = "Secrets Manager ARN of the RDS-managed master password (used only by the db-init job and DBAs)."
  value       = module.rds.master_user_secret_arn
}

output "kafka_mode" {
  description = "Kafka deployment mode in effect."
  value       = var.kafka_mode
}

output "msk_bootstrap_brokers_sasl_iam" {
  description = "MSK IAM bootstrap brokers (null when kafka_mode = redpanda)."
  value       = one(module.msk[*].bootstrap_brokers_sasl_iam)
}

output "msk_cluster_arn" {
  description = "MSK cluster ARN (null when kafka_mode = redpanda)."
  value       = one(module.msk[*].cluster_arn)
}

output "firmware_artifacts_bucket" {
  description = "Firmware artifacts bucket name."
  value       = module.s3.artifacts_bucket_name
}

output "firmware_artifacts_replica_bucket" {
  description = "Replica bucket name in replica_region (null when replication is disabled)."
  value       = module.s3.artifacts_replica_bucket_name
}

output "backups_bucket" {
  description = "Backups bucket name (database dumps, PKI exports)."
  value       = module.s3.backups_bucket_name
}

output "logs_bucket" {
  description = "Access-logs bucket name."
  value       = module.s3.logs_bucket_name
}

#------------------------------------------------------------------------------
# KMS / secrets
#------------------------------------------------------------------------------

output "kms_key_arns" {
  description = "Customer managed key ARNs by purpose."
  value       = module.kms.key_arns
}

output "kms_key_aliases" {
  description = "KMS alias names by purpose."
  value       = module.kms.alias_names
}

output "firmware_signing_secret_arn" {
  description = "Secrets Manager secret (encrypted under ironmesh-firmware-kek) that holds the Ed25519 firmware signing key. Populated by the ceremony, never by Terraform."
  value       = module.kms.firmware_signing_secret_arn
}

#------------------------------------------------------------------------------
# IAM
#------------------------------------------------------------------------------

output "irsa_role_arns" {
  description = "IRSA role ARNs per service; copy into the Helm values (services.<name>.serviceAccount.roleArn)."
  value       = module.iam.role_arns
}

output "ceremony_role_arn" {
  description = "Role assumed (with MFA) for CA ceremonies and firmware key wrapping."
  value       = module.iam.ceremony_role_arn
}

output "addon_role_arns" {
  description = "IRSA role ARNs of the cluster add-ons installed by Terraform."
  value = {
    aws_load_balancer_controller = module.eks_addons.alb_controller_role_arn
    cert_manager                 = module.eks_addons.cert_manager_role_arn
    external_dns                 = module.eks_addons.external_dns_role_arn
  }
}

#------------------------------------------------------------------------------
# Edge
#------------------------------------------------------------------------------

output "alb_dns_name" {
  description = "Application Load Balancer DNS name (console, registry, ota)."
  value       = module.alb.alb_dns_name
}

output "nlb_dns_name" {
  description = "Network Load Balancer DNS name (MQTT 8883, EST/OCSP 443, CRL 80)."
  value       = module.alb.nlb_dns_name
}

output "target_group_arns" {
  description = "Target group ARNs to bind with TargetGroupBinding resources from the Helm chart."
  value       = module.alb.target_group_arns
}

output "load_balancer_security_group_ids" {
  description = "Security groups of the ALB and NLB (referenced by TargetGroupBinding networking rules)."
  value = {
    alb = module.alb.alb_security_group_id
    nlb = module.alb.nlb_security_group_id
  }
}

output "waf_web_acl_arn" {
  description = "WAFv2 web ACL ARN attached to the ALB."
  value       = module.alb.waf_web_acl_arn
}

output "acm_certificate_arn" {
  description = "ACM wildcard certificate ARN for *.<domain>."
  value       = module.alb.acm_certificate_arn
}

output "public_hostnames" {
  description = "Public hostnames created in Route 53."
  value       = local.hosts
}

output "alerts_sns_topic_arn" {
  description = "SNS topic receiving CloudWatch alarms."
  value       = module.observability.sns_topic_arn
}

#------------------------------------------------------------------------------
# Helm hand-off
#------------------------------------------------------------------------------

output "helm_values" {
  description = "Ready-to-use values fragment for deploy/helm/ironmesh (terraform output -raw helm_values > values-<env>.generated.yaml)."
  value = yamlencode({
    global = {
      environment = var.environment
      domain      = var.domain
    }
    aws = {
      enabled = true
      region  = var.region
      targetGroupBindings = {
        enabled  = true
        console  = { arn = module.alb.target_group_arns["console"] }
        registry = { arn = module.alb.target_group_arns["registry"] }
        ota      = { arn = module.alb.target_group_arns["ota"] }
        emqx     = { arn = module.alb.target_group_arns["emqx"] }
        pkiMtls  = { arn = module.alb.target_group_arns["pki_mtls"] }
        pkiCrl   = { arn = module.alb.target_group_arns["pki_crl"] }
      }
      loadBalancerSecurityGroupIds = {
        alb = module.alb.alb_security_group_id
        nlb = module.alb.nlb_security_group_id
      }
    }
    database = {
      host    = module.rds.address
      port    = module.rds.port
      iamAuth = true
      cidrs   = module.network.isolated_subnet_cidrs
    }
    kafka = {
      mode             = var.kafka_mode
      bootstrapServers = local.use_msk ? one(module.msk[*].bootstrap_brokers_sasl_iam) : ""
      externalCidrs    = local.use_msk ? module.network.isolated_subnet_cidrs : []
    }
    externalSecrets = {
      enabled          = true
      secretPathPrefix = local.secrets_path_prefix
    }
    services = {
      pki = {
        serviceAccount = { roleArn = module.iam.role_arns["pki"] }
        config = {
          PKI_KMS_DEVICE_CA_KEY_ID   = module.kms.alias_names["device_ca"]
          PKI_KMS_SERVICES_CA_KEY_ID = module.kms.alias_names["services_ca"]
          PKI_KMS_BUNDLE_KEY_ID      = module.kms.alias_names["bundle_signing"]
          PKI_KMS_FACTORY_CA_KEY_ID  = lookup(module.kms.alias_names, "factory_ca", "")
          PKI_KMS_ROOT_CA_KEY_ID     = module.kms.alias_names["root_ca"]
        }
      }
      ota = {
        serviceAccount = { roleArn = module.iam.role_arns["ota"] }
        config = {
          OTA_ARTIFACT_BUCKET        = module.s3.artifacts_bucket_name
          OTA_S3_KMS_KEY_ARN         = module.kms.key_arns["s3"]
          OTA_SIGNING_KEK_KEY_ID     = module.kms.alias_names["firmware_kek"]
          OTA_SIGNING_KEY_SECRET_ARN = module.kms.firmware_signing_secret_arn
        }
      }
      policy   = { serviceAccount = { roleArn = module.iam.role_arns["policy"] } }
      registry = { serviceAccount = { roleArn = module.iam.role_arns["registry"] } }
      anomaly  = { serviceAccount = { roleArn = module.iam.role_arns["anomaly"] } }
      bridge   = { serviceAccount = { roleArn = module.iam.role_arns["bridge"] } }
    }
    backup = {
      serviceAccount = { roleArn = module.iam.role_arns["backup"] }
      bucket         = module.s3.backups_bucket_name
    }
  })
}
