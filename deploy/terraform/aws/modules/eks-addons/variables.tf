variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "vpc_id" {
  description = "VPC id (passed to the load balancer controller)."
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

variable "dns_zone_id" {
  description = "Route 53 hosted zone id managed by external-dns and cert-manager (DNS-01)."
  type        = string
}

variable "domain_filter" {
  description = "external-dns domain filter (the environment domain)."
  type        = string
}

variable "chart_versions" {
  description = "Pinned Helm chart versions."
  type = object({
    aws_load_balancer_controller = optional(string, "3.6.2")
    cert_manager                 = optional(string, "v1.21.3")
    external_dns                 = optional(string, "1.23.0")
  })
}

variable "partition" {
  description = "AWS partition."
  type        = string
}
