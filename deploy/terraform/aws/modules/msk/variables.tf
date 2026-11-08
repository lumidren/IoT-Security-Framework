variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "mode" {
  description = "msk-serverless or msk-provisioned."
  type        = string

  validation {
    condition     = contains(["msk-serverless", "msk-provisioned"], var.mode)
    error_message = "mode must be msk-serverless or msk-provisioned."
  }
}

variable "vpc_id" {
  description = "VPC id."
  type        = string
}

variable "subnet_ids" {
  description = "Isolated subnet ids for the brokers."
  type        = list(string)
}

variable "client_security_group_ids" {
  description = "Security groups allowed to reach the brokers (EKS cluster security group)."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "CMK for at-rest encryption (provisioned only; serverless uses an AWS-owned key)."
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "KMS key for the broker log group."
  type        = string
}

variable "log_retention_days" {
  description = "Broker log retention."
  type        = number
}

variable "kafka_version" {
  description = "Kafka version (provisioned only)."
  type        = string
}

variable "broker_instance_type" {
  description = "Broker instance type (provisioned only)."
  type        = string
}

variable "broker_count" {
  description = "Number of brokers (provisioned only)."
  type        = number
}

variable "ebs_volume_size_gb" {
  description = "Initial EBS size per broker (provisioned only)."
  type        = number
}
