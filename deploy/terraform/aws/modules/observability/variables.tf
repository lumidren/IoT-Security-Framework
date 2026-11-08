variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "alarm_email_endpoints" {
  description = "E-mail subscribers of the alerts topic."
  type        = list(string)
}

variable "alerts_kms_key_arn" {
  description = "CMK for the SNS topic."
  type        = string
}

variable "log_retention_days" {
  description = "Retention of the application log group."
  type        = number
}

variable "logs_kms_key_arn" {
  description = "KMS key for the application log group."
  type        = string
}

variable "rds_instance_identifier" {
  description = "RDS instance identifier."
  type        = string
}

variable "rds_free_storage_threshold_bytes" {
  description = "FreeStorageSpace alarm threshold in bytes."
  type        = number
}

variable "rds_freeable_memory_threshold_bytes" {
  description = "FreeableMemory alarm threshold in bytes."
  type        = number
  default     = 1073741824
}

variable "msk_cluster_name" {
  description = "Provisioned MSK cluster name; null disables MSK alarms (serverless/redpanda)."
  type        = string
  default     = null
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix (CloudWatch dimension)."
  type        = string
}

variable "alb_target_group_arn_suffixes" {
  description = "ALB target group ARN suffixes by name."
  type        = map(string)
}

variable "nlb_arn_suffix" {
  description = "NLB ARN suffix (CloudWatch dimension)."
  type        = string
}

variable "nlb_target_group_arn_suffixes" {
  description = "NLB target group ARN suffixes by name."
  type        = map(string)
}

variable "eks_cluster_name" {
  description = "EKS cluster name (Container Insights dimension)."
  type        = string
}

variable "enable_container_insights" {
  description = "Container Insights is installed; enables the node alarms."
  type        = bool
}

variable "waf_web_acl_name" {
  description = "WAF web ACL name for the blocked-requests alarm."
  type        = string
}

variable "region" {
  description = "AWS region (WAF metric dimension)."
  type        = string
}
