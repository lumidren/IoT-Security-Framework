output "identifier" {
  value = aws_db_instance.this.identifier
}

output "arn" {
  value = aws_db_instance.this.arn
}

output "address" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "resource_id" {
  description = "DbiResourceId used in rds-db:connect ARNs."
  value       = aws_db_instance.this.resource_id
}

output "master_user_secret_arn" {
  value = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "parameter_group_name" {
  value = aws_db_parameter_group.this.name
}
