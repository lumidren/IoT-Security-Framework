output "key_arns" {
  description = "Key ARNs by purpose (root_ca, factory_ca?, device_ca, services_ca, firmware_kek, bundle_kek, eks, rds, s3, logs, alerts, msk?)."
  value = merge(
    { for k, v in aws_kms_key.ca : k => v.arn },
    { for k, v in aws_kms_key.symmetric : k => v.arn },
  )
}

output "key_ids" {
  description = "Key ids by purpose."
  value = merge(
    { for k, v in aws_kms_key.ca : k => v.key_id },
    { for k, v in aws_kms_key.symmetric : k => v.key_id },
  )
}

output "alias_names" {
  description = "Alias names (alias/...) by purpose; services reference keys by alias."
  value = merge(
    { for k, v in aws_kms_alias.ca : k => v.name },
    { for k, v in aws_kms_alias.symmetric : k => v.name },
  )
}

output "firmware_signing_secret_arn" {
  value = aws_secretsmanager_secret.firmware_signing_key.arn
}

output "firmware_signing_secret_name" {
  value = aws_secretsmanager_secret.firmware_signing_key.name
}

output "bundle_signing_secret_arn" {
  description = "Secrets Manager secret (encrypted under bundle_kek) holding the Ed25519 PKI bundle signing seed."
  value       = aws_secretsmanager_secret.bundle_signing_key.arn
}

output "bundle_signing_secret_name" {
  value = aws_secretsmanager_secret.bundle_signing_key.name
}
