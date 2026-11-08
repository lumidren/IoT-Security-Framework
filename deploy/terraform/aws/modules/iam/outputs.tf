output "role_arns" {
  description = "IRSA role ARNs by service, plus external_secrets."
  value = merge(
    { for k, r in aws_iam_role.irsa : k => r.arn },
    { external_secrets = aws_iam_role.external_secrets.arn },
  )
}

output "ceremony_role_arn" {
  value = aws_iam_role.ceremony.arn
}
