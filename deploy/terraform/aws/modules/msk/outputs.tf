output "cluster_arn" {
  value = local.cluster_arn
}

output "cluster_name" {
  value = local.cluster_name
}

output "mode" {
  value = var.mode
}

output "bootstrap_brokers_sasl_iam" {
  description = "Comma-separated host:9098 bootstrap brokers (SASL/IAM over TLS)."
  value       = data.aws_msk_bootstrap_brokers.this.bootstrap_brokers_sasl_iam
}

output "security_group_id" {
  value = aws_security_group.this.id
}
