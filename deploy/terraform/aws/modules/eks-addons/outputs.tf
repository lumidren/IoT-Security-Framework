output "alb_controller_role_arn" {
  value = aws_iam_role.alb_controller.arn
}

output "cert_manager_role_arn" {
  value = aws_iam_role.cert_manager.arn
}

output "external_dns_role_arn" {
  value = aws_iam_role.external_dns.arn
}

output "default_storage_class" {
  value = kubernetes_storage_class_v1.gp3_encrypted.metadata[0].name
}
