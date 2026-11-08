# terraform apply -var-file=environments/staging.tfvars
#
# Staging trades availability for cost: single NAT gateway, single-AZ RDS, MSK Serverless,
# shorter retention. Everything security-relevant (encryption, TLS enforcement, WAF, Object
# Lock, deletion protection) stays identical to prod so that staging validates prod posture.

environment    = "staging"
region         = "eu-west-1"
replica_region = "eu-central-1"

dns_zone_name = "ironmesh.dev"
domain        = "staging.ironmesh.dev"

vpc_cidr           = "10.40.0.0/16"
az_count           = 3
single_nat_gateway = true

eks_version                    = "1.31"
cluster_endpoint_public_access = false
enable_container_insights      = false

node_groups = {
  general = {
    instance_types = ["m7i.large"]
    min_size       = 2
    max_size       = 5
    desired_size   = 3
    disk_size_gb   = 80
  }
}

kafka_mode = "msk-serverless"

rds_instance_class                      = "db.t4g.medium"
rds_multi_az                            = false
rds_allocated_storage_gb                = 50
rds_max_allocated_storage_gb            = 250
rds_backup_retention_days               = 14
rds_performance_insights_retention_days = 7
rds_deletion_protection                 = true

enable_artifact_replication         = false
artifact_object_lock_retention_days = 30
backup_retention_days               = 60
backup_object_lock_retention_days   = 14

waf_rate_limit     = 5000
log_retention_days = 30

alarm_email_endpoints = ["platform-alerts-staging@ironmesh.dev"]

tags = {
  CostCenter = "platform-staging"
}
