variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version."
  type        = string
}

variable "cluster_role_name" {
  description = "Name of the cluster IAM role (fixed up-front so KMS policies can reference it)."
  type        = string
}

variable "node_role_name" {
  description = "Name of the node IAM role."
  type        = string
}

variable "ebs_csi_role_name" {
  description = "Name of the EBS CSI driver IRSA role."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet ids for the control plane ENIs and the node groups."
  type        = list(string)
}

variable "endpoint_public_access" {
  description = "Enable the public API endpoint."
  type        = bool
}

variable "endpoint_public_access_cidrs" {
  description = "CIDRs allowed on the public API endpoint."
  type        = list(string)
}

variable "service_ipv4_cidr" {
  description = "Kubernetes service CIDR."
  type        = string
  default     = "172.20.0.0/16"
}

variable "secrets_kms_key_arn" {
  description = "KMS key for envelope encryption of Kubernetes secrets."
  type        = string
}

variable "ebs_kms_key_arn" {
  description = "KMS key for node root volumes and CSI volumes."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for the control plane log group."
  type        = string
}

variable "log_retention_days" {
  description = "Control plane log retention."
  type        = number
}

variable "node_groups" {
  description = "Managed node groups."
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
}

variable "admin_principal_arns" {
  description = "Additional cluster administrators (EKS access entries)."
  type        = list(string)
}

variable "enable_container_insights" {
  description = "Install the amazon-cloudwatch-observability add-on."
  type        = bool
}

variable "partition" {
  description = "AWS partition."
  type        = string
}

variable "tags" {
  description = "Tags applied to launch-template created instances and volumes (provider default_tags do not propagate there)."
  type        = map(string)
  default     = {}
}
