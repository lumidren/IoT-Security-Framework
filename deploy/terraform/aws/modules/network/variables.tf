variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR (/16 to /20)."
  type        = string
}

variable "az_count" {
  description = "Number of availability zones to use."
  type        = number
}

variable "cluster_name" {
  description = "EKS cluster name, used for the kubernetes.io/cluster/<name> subnet tags."
  type        = string
}

variable "single_nat_gateway" {
  description = "Create a single NAT gateway instead of one per AZ."
  type        = bool
  default     = false
}

variable "interface_endpoints" {
  description = "Interface VPC endpoint service short names (kms, ecr.api, ...)."
  type        = list(string)
}

variable "flow_log_retention_days" {
  description = "CloudWatch retention for VPC flow logs."
  type        = number
}

variable "flow_log_kms_key_arn" {
  description = "KMS key used to encrypt the flow log group."
  type        = string
}
