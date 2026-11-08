variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "account_id" {
  description = "AWS account id (bucket name uniqueness, log delivery policies)."
  type        = string
}

variable "region" {
  description = "Primary region."
  type        = string
}

variable "replica_region" {
  description = "Replication region."
  type        = string
}

variable "partition" {
  description = "AWS partition."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for the artifacts and backups buckets."
  type        = string
}

variable "enable_replication" {
  description = "Replicate firmware artifacts to replica_region."
  type        = bool
}

variable "replication_role_name" {
  description = "Fixed name of the replication role (referenced by the KMS key policy)."
  type        = string
}

variable "artifact_object_lock_retention_days" {
  description = "Default GOVERNANCE retention for firmware artifact versions."
  type        = number
}

variable "artifact_ia_transition_days" {
  description = "Days before artifacts move to STANDARD_IA."
  type        = number
}

variable "backup_retention_days" {
  description = "Expiration of backup objects."
  type        = number
}

variable "backup_object_lock_retention_days" {
  description = "Default GOVERNANCE retention for backup objects."
  type        = number
}

variable "kms_deletion_window_in_days" {
  description = "Deletion window for the replica-region key."
  type        = number
}
