#------------------------------------------------------------------------------
# Identity and placement
#------------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment. Drives naming, tagging and the environment-specific tfvars."
  type        = string

  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be one of: staging, prod."
  }
}

variable "name_prefix" {
  description = "Short project prefix used in every resource name (combined with the environment)."
  type        = string
  default     = "ironmesh"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 chars, lower-case alphanumerics and dashes, starting with a letter."
  }
}

variable "region" {
  description = "Primary AWS region."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.region))
    error_message = "region must look like eu-west-1 / us-gov-west-1."
  }
}

variable "replica_region" {
  description = "Secondary region used for S3 cross-region replication of firmware artifacts and backups."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.replica_region))
    error_message = "replica_region must look like eu-central-1."
  }
}

variable "tags" {
  description = "Additional tags merged into the default tag set (Project, Environment, ManagedBy)."
  type        = map(string)
  default     = {}
}

#------------------------------------------------------------------------------
# DNS / TLS
#------------------------------------------------------------------------------

variable "dns_zone_name" {
  description = "Name of the public Route 53 hosted zone that already exists in the account (looked up, never created)."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", var.dns_zone_name))
    error_message = "dns_zone_name must be a fully qualified DNS name without trailing dot, e.g. ironmesh.dev."
  }
}

variable "domain" {
  description = "Environment domain under dns_zone_name. Records created: console., registry., ota., pki., mqtt. and the ACM wildcard."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", var.domain))
    error_message = "domain must be a fully qualified DNS name, e.g. staging.ironmesh.dev."
  }
}

#------------------------------------------------------------------------------
# Network
#------------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "VPC CIDR. Split into public / private / isolated subnets across az_count availability zones."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && tonumber(split("/", var.vpc_cidr)[1]) <= 20 && tonumber(split("/", var.vpc_cidr)[1]) >= 16
    error_message = "vpc_cidr must be a valid IPv4 CIDR between /16 and /20."
  }
}

variable "az_count" {
  description = "Number of availability zones to span (3 recommended for Multi-AZ RDS/MSK and EKS spread)."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

variable "single_nat_gateway" {
  description = "Use one NAT gateway for all private subnets (cheaper, not HA). Keep false in prod."
  type        = bool
  default     = false
}

variable "vpc_interface_endpoints" {
  description = "Interface VPC endpoints to create (S3 is always created as a gateway endpoint)."
  type        = list(string)
  default     = ["kms", "ecr.api", "ecr.dkr", "sts", "logs", "secretsmanager"]

  validation {
    condition     = alltrue([for e in var.vpc_interface_endpoints : can(regex("^[a-z0-9.-]+$", e))])
    error_message = "Endpoint service short names only, e.g. kms, ecr.api, ecr.dkr, sts, logs, secretsmanager."
  }
}

#------------------------------------------------------------------------------
# EKS
#------------------------------------------------------------------------------

variable "eks_version" {
  description = "Kubernetes control plane version."
  type        = string
  default     = "1.31"

  validation {
    condition     = can(regex("^1\\.(2[8-9]|3[0-9])$", var.eks_version))
    error_message = "eks_version must be 1.28 or newer (format 1.NN)."
  }
}

variable "cluster_endpoint_public_access" {
  description = "Expose the EKS API endpoint publicly (restricted by cluster_endpoint_public_access_cidrs). Private access is always on."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDRs allowed to reach the public EKS API endpoint when enabled. Never 0.0.0.0/0 in prod."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.cluster_endpoint_public_access_cidrs : can(cidrhost(c, 0))])
    error_message = "Every entry must be a valid IPv4 CIDR."
  }
}

variable "cluster_admin_principal_arns" {
  description = "IAM principal ARNs granted AmazonEKSClusterAdminPolicy through EKS access entries (the applying identity is admin by default)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.cluster_admin_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "Entries must be IAM role or user ARNs."
  }
}

variable "node_groups" {
  description = "EKS managed node groups keyed by name."
  type = map(object({
    instance_types = list(string)
    capacity_type  = optional(string, "ON_DEMAND")
    ami_type       = optional(string, "AL2023_x86_64_STANDARD")
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_size_gb   = optional(number, 100)
    labels         = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = optional(string)
      effect = string
    })), [])
  }))
  default = {
    general = {
      instance_types = ["m7i.xlarge"]
      min_size       = 3
      max_size       = 9
      desired_size   = 3
    }
  }

  validation {
    condition     = alltrue([for k, ng in var.node_groups : ng.min_size <= ng.desired_size && ng.desired_size <= ng.max_size && ng.min_size >= 1])
    error_message = "Each node group needs 1 <= min_size <= desired_size <= max_size."
  }

  validation {
    condition     = alltrue([for k, ng in var.node_groups : contains(["ON_DEMAND", "SPOT"], ng.capacity_type)])
    error_message = "capacity_type must be ON_DEMAND or SPOT."
  }
}

variable "enable_container_insights" {
  description = "Install the amazon-cloudwatch-observability add-on (Container Insights). Required for the EKS node-not-ready alarm."
  type        = bool
  default     = true
}

variable "irsa_service_account_prefix" {
  description = "Prefix of the Kubernetes ServiceAccounts created by the Helm chart (release name). IRSA trust is bound to <prefix>-<service>."
  type        = string
  default     = "ironmesh"
}

variable "kubernetes_namespace" {
  description = "Namespace the IronMesh Helm release is installed into (IRSA trust policies are scoped to it)."
  type        = string
  default     = "ironmesh"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.kubernetes_namespace))
    error_message = "kubernetes_namespace must be a valid DNS-1123 label."
  }
}

variable "external_secrets_namespace" {
  description = "Namespace of the External Secrets Operator (its ServiceAccount receives the IRSA role for Secrets Manager)."
  type        = string
  default     = "external-secrets"
}

variable "external_secrets_service_account" {
  description = "ServiceAccount name of the External Secrets Operator."
  type        = string
  default     = "external-secrets"
}

variable "helm_chart_versions" {
  description = "Pinned chart versions for the cluster add-ons installed by Terraform."
  type = object({
    aws_load_balancer_controller = optional(string, "3.6.2")
    cert_manager                 = optional(string, "v1.21.3")
    external_dns                 = optional(string, "1.23.0")
  })
  default = {}
}

#------------------------------------------------------------------------------
# KMS / PKI
#------------------------------------------------------------------------------

variable "kms_admin_principal_arns" {
  description = "IAM principals allowed to administer (but never use for signing) the CA keys. The identity running Terraform is always included."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.kms_admin_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "Entries must be IAM role or user ARNs."
  }
}

variable "ceremony_principal_arns" {
  description = "IAM principals allowed to assume the CA ceremony role (root CA signing, firmware key wrapping). Defaults to the applying identity."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.ceremony_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "Entries must be IAM role or user ARNs."
  }
}

variable "root_ca_require_mfa" {
  description = "Require an MFA-authenticated session for kms:Sign with the root CA key and for assuming the ceremony role."
  type        = bool
  default     = true
}

variable "create_factory_ca_key" {
  description = "Create the Factory CA signing key (P-384). Set false when the factory CA is operated from a separate account/HSM."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "Waiting period before a scheduled KMS key deletion becomes effective."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

#------------------------------------------------------------------------------
# Kafka (MSK or self-hosted Redpanda)
#------------------------------------------------------------------------------

variable "kafka_mode" {
  description = "msk-serverless | msk-provisioned | redpanda. With redpanda no MSK resources are created and the Helm chart runs Redpanda on EKS."
  type        = string
  default     = "msk-provisioned"

  validation {
    condition     = contains(["msk-serverless", "msk-provisioned", "redpanda"], var.kafka_mode)
    error_message = "kafka_mode must be msk-serverless, msk-provisioned or redpanda."
  }
}

variable "msk_kafka_version" {
  description = "Apache Kafka version for provisioned MSK."
  type        = string
  default     = "3.6.0"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.msk_kafka_version))
    error_message = "msk_kafka_version must be a semantic version such as 3.6.0."
  }
}

variable "msk_broker_instance_type" {
  description = "Broker instance type for provisioned MSK."
  type        = string
  default     = "kafka.m7g.large"

  validation {
    condition     = can(regex("^kafka\\.", var.msk_broker_instance_type))
    error_message = "msk_broker_instance_type must start with kafka."
  }
}

variable "msk_broker_count" {
  description = "Total number of brokers (must be a multiple of az_count)."
  type        = number
  default     = 3

  validation {
    condition     = var.msk_broker_count >= 2 && var.msk_broker_count <= 30
    error_message = "msk_broker_count must be between 2 and 30."
  }
}

variable "msk_ebs_volume_size_gb" {
  description = "Initial EBS volume per broker (storage auto-scaling grows it up to 4x)."
  type        = number
  default     = 500

  validation {
    condition     = var.msk_ebs_volume_size_gb >= 100 && var.msk_ebs_volume_size_gb <= 16384
    error_message = "msk_ebs_volume_size_gb must be between 100 and 16384."
  }
}

#------------------------------------------------------------------------------
# RDS
#------------------------------------------------------------------------------

variable "rds_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.r6g.large"

  validation {
    condition     = can(regex("^db\\.", var.rds_instance_class))
    error_message = "rds_instance_class must start with db."
  }
}

variable "rds_engine_version" {
  description = "PostgreSQL engine version (major 16)."
  type        = string
  default     = "16.4"

  validation {
    condition     = can(regex("^16\\.[0-9]+$", var.rds_engine_version))
    error_message = "rds_engine_version must be a PostgreSQL 16.x version."
  }
}

variable "rds_multi_az" {
  description = "Multi-AZ standby. Required in prod."
  type        = bool
  default     = true
}

variable "rds_allocated_storage_gb" {
  description = "Initial gp3 storage."
  type        = number
  default     = 100

  validation {
    condition     = var.rds_allocated_storage_gb >= 20 && var.rds_allocated_storage_gb <= 65536
    error_message = "rds_allocated_storage_gb must be between 20 and 65536."
  }
}

variable "rds_max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling (must be >= rds_allocated_storage_gb)."
  type        = number
  default     = 1000

  validation {
    condition     = var.rds_max_allocated_storage_gb >= 20 && var.rds_max_allocated_storage_gb <= 65536
    error_message = "rds_max_allocated_storage_gb must be between 20 and 65536."
  }
}

variable "rds_backup_retention_days" {
  description = "Automated backup retention (PITR window)."
  type        = number
  default     = 35

  validation {
    condition     = var.rds_backup_retention_days >= 7 && var.rds_backup_retention_days <= 35
    error_message = "rds_backup_retention_days must be between 7 and 35."
  }
}

variable "rds_performance_insights_retention_days" {
  description = "Performance Insights retention: 7 (free), 731, or a multiple of 31 up to 731."
  type        = number
  default     = 731

  validation {
    condition     = var.rds_performance_insights_retention_days == 7 || var.rds_performance_insights_retention_days == 731 || (var.rds_performance_insights_retention_days % 31 == 0 && var.rds_performance_insights_retention_days <= 731)
    error_message = "Allowed values: 7, 731, or a multiple of 31 up to 731."
  }
}

variable "rds_deletion_protection" {
  description = "Deletion protection on the DB instance."
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# S3
#------------------------------------------------------------------------------

variable "artifact_object_lock_retention_days" {
  description = "Default Object Lock retention (GOVERNANCE) applied to every firmware artifact version."
  type        = number
  default     = 365

  validation {
    condition     = var.artifact_object_lock_retention_days >= 1 && var.artifact_object_lock_retention_days <= 3650
    error_message = "artifact_object_lock_retention_days must be between 1 and 3650."
  }
}

variable "artifact_ia_transition_days" {
  description = "Days before firmware artifacts transition to STANDARD_IA."
  type        = number
  default     = 90

  validation {
    condition     = var.artifact_ia_transition_days >= 30
    error_message = "STANDARD_IA transitions require at least 30 days."
  }
}

variable "enable_artifact_replication" {
  description = "Replicate the firmware artifacts bucket to replica_region (verified by scripts/backup/firmware_backup.sh)."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Expiry of objects in the backups bucket (database dumps, PKI exports)."
  type        = number
  default     = 400

  validation {
    condition     = var.backup_retention_days >= 35
    error_message = "backup_retention_days must be at least 35 (matches the RDS PITR window)."
  }
}

variable "backup_object_lock_retention_days" {
  description = "Object Lock (GOVERNANCE) retention for backup objects, protecting dumps from deletion by a compromised credential."
  type        = number
  default     = 35

  validation {
    condition     = var.backup_object_lock_retention_days >= 1 && var.backup_object_lock_retention_days <= 3650
    error_message = "backup_object_lock_retention_days must be between 1 and 3650."
  }
}

#------------------------------------------------------------------------------
# Edge (ALB / NLB / WAF)
#------------------------------------------------------------------------------

variable "waf_rate_limit" {
  description = "Requests per 5-minute window per source IP before the WAF rate-based rule blocks."
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 100 && var.waf_rate_limit <= 2000000000
    error_message = "waf_rate_limit must be between 100 and 2,000,000,000."
  }
}

variable "alb_access_logs_enabled" {
  description = "Write ALB access logs to the logs bucket."
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# Observability
#------------------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch Logs retention for every log group created here."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be one of the retention values accepted by CloudWatch Logs."
  }
}

variable "alarm_email_endpoints" {
  description = "E-mail addresses subscribed to the alerts SNS topic (subscriptions must be confirmed)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.alarm_email_endpoints : can(regex("^[^@\\s]+@[^@\\s]+\\.[a-z]{2,}$", e))])
    error_message = "Every entry must be an e-mail address."
  }
}

variable "rds_free_storage_alarm_gb" {
  description = "RDS FreeStorageSpace alarm threshold in GiB."
  type        = number
  default     = 20

  validation {
    condition     = var.rds_free_storage_alarm_gb >= 1
    error_message = "rds_free_storage_alarm_gb must be >= 1."
  }
}
