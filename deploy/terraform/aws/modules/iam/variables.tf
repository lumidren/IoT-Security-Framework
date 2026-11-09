variable "account_id" {
  description = "AWS account id."
  type        = string
}

variable "partition" {
  description = "AWS partition."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "oidc_provider_arn" {
  description = "IRSA OIDC provider ARN."
  type        = string
}

variable "oidc_provider_url" {
  description = "IRSA OIDC provider URL without scheme."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace of the IronMesh release."
  type        = string
}

variable "service_account_names" {
  description = "ServiceAccount name per service (pki, policy, bridge, registry, ota, anomaly, backup)."
  type        = map(string)
}

variable "role_names" {
  description = "IAM role name per service (fixed up-front; referenced by KMS key policies)."
  type        = map(string)
}

variable "external_secrets_role_name" {
  description = "Role name for the External Secrets Operator."
  type        = string
}

variable "external_secrets_namespace" {
  description = "Namespace of the External Secrets Operator."
  type        = string
}

variable "external_secrets_service_account" {
  description = "ServiceAccount of the External Secrets Operator."
  type        = string
}

variable "secrets_path_prefix" {
  description = "Secrets Manager name prefix synced by External Secrets (ironmesh/<env>/)."
  type        = string
}

variable "ceremony_role_name" {
  description = "Name of the CA ceremony role."
  type        = string
}

variable "ceremony_principal_arns" {
  description = "Principals allowed to assume the ceremony role."
  type        = list(string)
}

variable "ceremony_require_mfa" {
  description = "Require MFA to assume the ceremony role."
  type        = bool
}

variable "kms_key_arns" {
  description = "Key ARNs by purpose from modules/kms."
  type        = map(string)
}

variable "firmware_signing_secret_arn" {
  description = "Secrets Manager ARN of the wrapped firmware signing key."
  type        = string
}

variable "bundle_signing_secret_arn" {
  description = "Secrets Manager ARN of the wrapped Ed25519 PKI bundle signing seed."
  type        = string
}

variable "artifacts_bucket_arn" {
  description = "Firmware artifacts bucket ARN."
  type        = string
}

variable "artifacts_replica_bucket_arn" {
  description = "Firmware artifacts replica bucket ARN (null when replication is disabled)."
  type        = string
  default     = null
}

variable "backups_bucket_arn" {
  description = "Backups bucket ARN."
  type        = string
}

variable "rds_resource_id" {
  description = "RDS DbiResourceId for rds-db:connect ARNs."
  type        = string
}

variable "db_users" {
  description = "Database role per service (pki, registry, ota, anomaly, backup)."
  type        = map(string)
}

variable "kafka_mode" {
  description = "msk-serverless | msk-provisioned | redpanda."
  type        = string
}

variable "msk_cluster_arn" {
  description = "MSK cluster ARN (null with redpanda)."
  type        = string
  default     = null
}
