variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "vpc_id" {
  description = "VPC id."
  type        = string
}

variable "subnet_ids" {
  description = "Isolated subnet ids."
  type        = list(string)
}

variable "client_security_group_ids" {
  description = "Security groups allowed to connect on 5432 (EKS cluster security group)."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "CMK for storage, Performance Insights and the managed master secret."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for exported log groups."
  type        = string
}

variable "log_retention_days" {
  description = "Retention of exported PostgreSQL logs."
  type        = number
}

variable "instance_class" {
  description = "Instance class."
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL 16.x version."
  type        = string
}

variable "multi_az" {
  description = "Multi-AZ deployment."
  type        = bool
}

variable "allocated_storage_gb" {
  description = "Initial storage."
  type        = number
}

variable "max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling."
  type        = number
}

variable "backup_retention_days" {
  description = "Automated backup retention."
  type        = number
}

variable "performance_insights_retention_days" {
  description = "Performance Insights retention."
  type        = number
}

variable "deletion_protection" {
  description = "Deletion protection."
  type        = bool
}

variable "master_username" {
  description = "Master user name (password is generated and stored by RDS in Secrets Manager)."
  type        = string
  default     = "ironmesh_admin"
}
