#------------------------------------------------------------------------------
# Edge
#
#   ALB (HTTPS, WAFv2)  console.<domain> -> console:3000
#                        registry.<domain> -> registry:8000
#                        ota.<domain>      -> ota:8001
#   NLB (TCP passthrough) mqtt.<domain>:8883 -> emqx:8883   (TLS 1.3 + mTLS terminated by EMQX)
#                         pki.<domain>:443   -> pki:8443    (EST/OCSP/API, mTLS terminated by pki)
#                         pki.<domain>:80    -> pki:8444    (CRL, plain HTTP by design)
#
# Pods are registered through TargetGroupBinding resources created by the Helm chart.
#------------------------------------------------------------------------------

locals {
  alb_targets = {
    console = {
      port        = 3000
      health_path = "/healthz"
      host        = var.hosts["console"]
    }
    registry = {
      port        = 8000
      health_path = "/healthz"
      host        = var.hosts["registry"]
    }
    ota = {
      port        = 8001
      health_path = "/healthz"
      host        = var.hosts["ota"]
    }
  }

  # The broker is health-checked with a plain TCP connect on its own MQTT port: the EMQX
  # management API (18083) is never reachable from the NLB or the VPC CIDR (THREAT_MODEL T-76),
  # so no security group rule opens it.
  nlb_targets = {
    emqx = {
      port            = 8883
      listener_port   = 8883
      health_protocol = "TCP"
      health_port     = 8883
      health_path     = ""
    }
    pki_mtls = {
      port            = 8443
      listener_port   = 443
      health_protocol = "HTTP"
      health_port     = 8444
      health_path     = "/healthz"
    }
    pki_crl = {
      port            = 8444
      listener_port   = 80
      health_protocol = "HTTP"
      health_port     = 8444
      health_path     = "/healthz"
    }
  }

  alb_record_hosts = { for k in ["console", "registry", "ota"] : k => var.hosts[k] }
  nlb_record_hosts = { for k in ["pki", "mqtt"] : k => var.hosts[k] }

  managed_rule_groups = {
    AWSManagedRulesAmazonIpReputationList = { priority = 10, count_rules = [] }
    AWSManagedRulesCommonRuleSet          = { priority = 20, count_rules = ["SizeRestrictions_BODY"] }
    AWSManagedRulesKnownBadInputsRuleSet  = { priority = 30, count_rules = [] }
    AWSManagedRulesSQLiRuleSet            = { priority = 40, count_rules = [] }
  }
}

#------------------------------------------------------------------------------
# ACM certificate (DNS validated)
#------------------------------------------------------------------------------

resource "aws_acm_certificate" "this" {
  domain_name               = var.domain
  subject_alternative_names = ["*.${var.domain}"]
  validation_method         = "DNS"

  options {
    certificate_transparency_logging_preference = "ENABLED"
  }

  tags = {
    Name = "${var.name_prefix}-edge"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id         = var.dns_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

#------------------------------------------------------------------------------
# Security groups
#------------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-edge-alb"
  description = "Internet-facing ALB: HTTPS/HTTP in, pods out"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-edge-alb"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_v4" {
  for_each = toset(["80", "443"])

  security_group_id = aws_security_group.alb.id
  description       = "Public ${each.value}/tcp"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_v6" {
  for_each = toset(["80", "443"])

  security_group_id = aws_security_group.alb.id
  description       = "Public ${each.value}/tcp (IPv6)"
  cidr_ipv6         = "::/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb" {
  security_group_id = aws_security_group.alb.id
  description       = "To pods in the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 1024
  to_port           = 65535
}

resource "aws_security_group" "nlb" {
  name        = "${var.name_prefix}-edge-nlb"
  description = "Internet-facing NLB: MQTT 8883, EST/OCSP 443, CRL 80 in, pods out"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-edge-nlb"
  }
}

resource "aws_vpc_security_group_ingress_rule" "nlb_v4" {
  for_each = toset(["80", "443", "8883"])

  security_group_id = aws_security_group.nlb.id
  description       = "Public ${each.value}/tcp"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "nlb_v6" {
  for_each = toset(["80", "443", "8883"])

  security_group_id = aws_security_group.nlb.id
  description       = "Public ${each.value}/tcp (IPv6)"
  cidr_ipv6         = "::/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "nlb" {
  security_group_id = aws_security_group.nlb.id
  description       = "To pods in the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 1024
  to_port           = 65535
}

# Pods (EKS cluster security group) accept traffic only from the load balancers on the
# service ports. TargetGroupBinding.networking is therefore left unset in the Helm chart.
resource "aws_vpc_security_group_ingress_rule" "pods_from_alb" {
  for_each = local.alb_targets

  security_group_id            = var.cluster_security_group_id
  description                  = "ALB to ${each.key}"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = each.value.port
  to_port                      = each.value.port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "pods_from_nlb" {
  for_each = { for k, v in local.nlb_targets : k => v.port }

  security_group_id            = var.cluster_security_group_id
  description                  = "NLB to ${each.key}"
  referenced_security_group_id = aws_security_group.nlb.id
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
}

# Health-check ports that differ from the traffic port (pki 8444 for the 8443 target group). The
# broker is checked on 8883 itself, so 18083 never appears here.
resource "aws_vpc_security_group_ingress_rule" "pods_from_nlb_healthcheck" {
  for_each = toset([for k, v in local.nlb_targets : tostring(v.health_port) if v.health_port != v.port])

  security_group_id            = var.cluster_security_group_id
  description                  = "NLB health checks ${each.value}"
  referenced_security_group_id = aws_security_group.nlb.id
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
  ip_protocol                  = "tcp"
}

#------------------------------------------------------------------------------
# WAFv2
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "waf" {
  # WAF requires the aws-waf-logs- prefix.
  name              = "aws-waf-logs-${var.name_prefix}-edge"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name_prefix}-edge"
  description = "IronMesh public API/console protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 0

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = var.waf_rate_limit
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-per-ip"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.managed_rule_groups

    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"

          # Firmware uploads exceed the 8 KiB body inspection limit; keep the rule in count mode.
          dynamic "rule_action_override" {
            for_each = toset(rule.value.count_rules)

            content {
              name = rule_action_override.value

              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-edge"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${var.name_prefix}-edge"
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

#------------------------------------------------------------------------------
# Application Load Balancer
#------------------------------------------------------------------------------

resource "aws_lb" "alb" {
  name               = "${var.name_prefix}-edge-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
  preserve_host_header       = true
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 60

  access_logs {
    bucket  = var.access_logs_bucket_name
    prefix  = "alb"
    enabled = var.access_logs_enabled
  }

  tags = {
    Name = "${var.name_prefix}-edge-alb"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

resource "aws_lb_target_group" "alb" {
  for_each = local.alb_targets

  name                          = "${var.name_prefix}-${each.key}"
  port                          = each.value.port
  protocol                      = "HTTP"
  target_type                   = "ip"
  vpc_id                        = var.vpc_id
  deregistration_delay          = 30
  load_balancing_algorithm_type = "least_outstanding_requests"

  health_check {
    protocol            = "HTTP"
    path                = each.value.health_path
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.name_prefix}-${each.key}"
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = aws_acm_certificate_validation.this.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      # ALB fixed responses accept only text/plain, text/css, text/html, application/javascript
      # and application/json, so the problem-details body is served as application/json.
      content_type = "application/json"
      message_body = "{\"type\":\"about:blank\",\"title\":\"Not Found\",\"status\":404}"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "host" {
  for_each = local.alb_targets

  listener_arn = aws_lb_listener.https.arn
  priority     = 10 * (index(keys(local.alb_targets), each.key) + 1)

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb[each.key].arn
  }

  condition {
    host_header {
      values = [each.value.host]
    }
  }
}

#------------------------------------------------------------------------------
# Network Load Balancer (TLS passthrough)
#------------------------------------------------------------------------------

resource "aws_lb" "nlb" {
  name               = "${var.name_prefix}-edge-nlb"
  load_balancer_type = "network"
  internal           = false
  security_groups    = [aws_security_group.nlb.id]
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.deletion_protection

  tags = {
    Name = "${var.name_prefix}-edge-nlb"
  }
}

resource "aws_lb_target_group" "nlb" {
  for_each = local.nlb_targets

  name                   = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  port                   = each.value.port
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = var.vpc_id
  preserve_client_ip     = "true"
  connection_termination = true
  deregistration_delay   = 60

  health_check {
    protocol            = each.value.health_protocol
    port                = tostring(each.value.health_port)
    path                = each.value.health_protocol == "HTTP" ? each.value.health_path : null
    matcher             = each.value.health_protocol == "HTTP" ? "200-399" : null
    interval            = 15
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  }
}

resource "aws_lb_listener" "nlb" {
  for_each = local.nlb_targets

  load_balancer_arn = aws_lb.nlb.arn
  port              = each.value.listener_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nlb[each.key].arn
  }
}

#------------------------------------------------------------------------------
# DNS
#------------------------------------------------------------------------------

resource "aws_route53_record" "alb" {
  for_each = local.alb_record_hosts

  zone_id = var.dns_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "nlb" {
  for_each = local.nlb_record_hosts

  zone_id = var.dns_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = aws_lb.nlb.dns_name
    zone_id                = aws_lb.nlb.zone_id
    evaluate_target_health = true
  }
}
