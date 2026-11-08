variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "vpc_id" {
  description = "VPC id."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR (load balancer egress)."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet ids."
  type        = list(string)
}

variable "domain" {
  description = "Environment domain; the ACM certificate covers <domain> and *.<domain>."
  type        = string
}

variable "hosts" {
  description = "Hostnames: console, registry, ota (ALB) and pki, mqtt (NLB)."
  type        = map(string)
}

variable "dns_zone_id" {
  description = "Route 53 hosted zone id."
  type        = string
}

variable "cluster_security_group_id" {
  description = "EKS cluster security group that receives ingress rules from the load balancers."
  type        = string
}

variable "access_logs_enabled" {
  description = "Enable ALB access logs."
  type        = bool
}

variable "access_logs_bucket_name" {
  description = "Bucket for ALB access logs (SSE-S3)."
  type        = string
}

variable "waf_rate_limit" {
  description = "Rate-based rule limit per 5 minutes per IP."
  type        = number
}

variable "log_retention_days" {
  description = "WAF log retention."
  type        = number
}

variable "logs_kms_key_arn" {
  description = "KMS key for the WAF log group."
  type        = string
}

variable "ssl_policy" {
  description = "ALB TLS policy."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "deletion_protection" {
  description = "Deletion protection on both load balancers."
  type        = bool
  default     = true
}
