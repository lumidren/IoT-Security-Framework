output "alb_arn" {
  value = aws_lb.alb.arn
}

output "alb_arn_suffix" {
  value = aws_lb.alb.arn_suffix
}

output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "alb_zone_id" {
  value = aws_lb.alb.zone_id
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "nlb_arn" {
  value = aws_lb.nlb.arn
}

output "nlb_arn_suffix" {
  value = aws_lb.nlb.arn_suffix
}

output "nlb_dns_name" {
  value = aws_lb.nlb.dns_name
}

output "nlb_zone_id" {
  value = aws_lb.nlb.zone_id
}

output "nlb_security_group_id" {
  value = aws_security_group.nlb.id
}

output "target_group_arns" {
  description = "Target group ARNs: console, registry, ota (ALB) and emqx, pki_mtls, pki_crl (NLB)."
  value = merge(
    { for k, v in aws_lb_target_group.alb : k => v.arn },
    { for k, v in aws_lb_target_group.nlb : k => v.arn },
  )
}

output "alb_target_group_arn_suffixes" {
  value = { for k, v in aws_lb_target_group.alb : k => v.arn_suffix }
}

output "nlb_target_group_arn_suffixes" {
  value = { for k, v in aws_lb_target_group.nlb : k => v.arn_suffix }
}

output "waf_web_acl_arn" {
  value = aws_wafv2_web_acl.this.arn
}

output "waf_web_acl_name" {
  value = aws_wafv2_web_acl.this.name
}

output "acm_certificate_arn" {
  value = aws_acm_certificate_validation.this.certificate_arn
}

output "record_fqdns" {
  value = merge(
    { for k, v in aws_route53_record.alb : k => v.fqdn },
    { for k, v in aws_route53_record.nlb : k => v.fqdn },
  )
}
