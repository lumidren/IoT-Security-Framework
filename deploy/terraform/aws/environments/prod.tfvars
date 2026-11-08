# terraform apply -var-file=environments/prod.tfvars
#
# Account-specific principals (kms_admin_principal_arns, ceremony_principal_arns,
# cluster_admin_principal_arns) are intentionally not in version control. Pass them with
# -var-file=environments/prod.principals.tfvars (git-ignored) or TF_VAR_* variables.

environment    = "prod"
region         = "eu-west-1"
replica_region = "eu-central-1"

dns_zone_name = "ironmesh.dev"
domain        = "ironmesh.dev"

vpc_cidr           = "10.50.0.0/16"
az_count           = 3
single_nat_gateway = false

eks_version                    = "1.31"
cluster_endpoint_public_access = false
enable_container_insights      = true

node_groups = {
  general = {
    instance_types = ["m7i.xlarge"]
    min_size       = 3
    max_size       = 12
    desired_size   = 3
    disk_size_gb   = 100
  }
  broker = {
    instance_types = ["c7i.xlarge"]
    min_size       = 3
    max_size       = 6
    desired_size   = 3
    disk_size_gb   = 100
    labels         = { "ironmesh.dev/workload" = "broker" }
    taints = [{
      key    = "ironmesh.dev/workload"
      value  = "broker"
      effect = "NO_SCHEDULE"
    }]
  }
}

kafka_mode               = "msk-provisioned"
msk_kafka_version        = "3.6.0"
msk_broker_instance_type = "kafka.m7g.large"
msk_broker_count         = 3
msk_ebs_volume_size_gb   = 500

rds_instance_class                      = "db.r6g.large"
rds_multi_az                            = true
rds_allocated_storage_gb                = 200
rds_max_allocated_storage_gb            = 2000
rds_backup_retention_days               = 35
rds_performance_insights_retention_days = 731
rds_deletion_protection                 = true

enable_artifact_replication         = true
artifact_object_lock_retention_days = 365
artifact_ia_transition_days         = 90
backup_retention_days               = 400
backup_object_lock_retention_days   = 35

waf_rate_limit     = 2000
log_retention_days = 365

alarm_email_endpoints = ["platform-alerts@ironmesh.dev"]

tags = {
  CostCenter = "platform-prod"
}
