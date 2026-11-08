#------------------------------------------------------------------------------
# Alerting channel
#------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.alerts_kms_key_arn

  tags = {
    Name = "${var.name_prefix}-alerts"
  }
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AllowCloudWatchAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alarm_email_endpoints)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

#------------------------------------------------------------------------------
# Application log group (fluent-bit / CloudWatch agent destination)
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "application" {
  name              = "/ironmesh/${var.name_prefix}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

locals {
  actions = [aws_sns_topic.alerts.arn]
}

#------------------------------------------------------------------------------
# RDS
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name_prefix}-rds-cpu-high"
  alarm_description   = "PostgreSQL CPU above 80% for 15 minutes"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.name_prefix}-rds-free-storage-low"
  alarm_description   = "PostgreSQL free storage below threshold (autoscaling ceiling may be reached)"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = var.rds_free_storage_threshold_bytes
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_memory" {
  alarm_name          = "${var.name_prefix}-rds-freeable-memory-low"
  alarm_description   = "PostgreSQL freeable memory below threshold"
  namespace           = "AWS/RDS"
  metric_name         = "FreeableMemory"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 3
  threshold           = var.rds_freeable_memory_threshold_bytes
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_identifier
  }
}

#------------------------------------------------------------------------------
# MSK (provisioned only)
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "msk_disk" {
  count = var.msk_cluster_name != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-msk-disk-high"
  alarm_description   = "Kafka data log disk usage above 80% on any broker"
  namespace           = "AWS/Kafka"
  metric_name         = "KafkaDataLogsDiskUsed"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    "Cluster Name" = var.msk_cluster_name
  }
}

resource "aws_cloudwatch_metric_alarm" "msk_offline_partitions" {
  count = var.msk_cluster_name != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-msk-offline-partitions"
  alarm_description   = "Kafka partitions without an active leader"
  namespace           = "AWS/Kafka"
  metric_name         = "OfflinePartitionsCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    "Cluster Name" = var.msk_cluster_name
  }
}

resource "aws_cloudwatch_metric_alarm" "msk_controller" {
  count = var.msk_cluster_name != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-msk-no-active-controller"
  alarm_description   = "Kafka cluster has no active controller"
  namespace           = "AWS/Kafka"
  metric_name         = "ActiveControllerCount"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    "Cluster Name" = var.msk_cluster_name
  }
}

#------------------------------------------------------------------------------
# ALB
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "alb_5xx_ratio" {
  alarm_name          = "${var.name_prefix}-alb-5xx-ratio-high"
  alarm_description   = "More than 5% of ALB requests answered 5xx (ELB or targets) over 10 minutes"
  evaluation_periods  = 2
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  metric_query {
    id          = "ratio"
    expression  = "IF(requests > 0, 100 * (FILL(elb5xx, 0) + FILL(target5xx, 0)) / requests, 0)"
    label       = "5xx percentage"
    return_data = true
  }

  metric_query {
    id = "requests"

    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "RequestCount"
      period      = 300
      stat        = "Sum"

      dimensions = {
        LoadBalancer = var.alb_arn_suffix
      }
    }
  }

  metric_query {
    id = "elb5xx"

    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_ELB_5XX_Count"
      period      = 300
      stat        = "Sum"

      dimensions = {
        LoadBalancer = var.alb_arn_suffix
      }
    }
  }

  metric_query {
    id = "target5xx"

    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_Target_5XX_Count"
      period      = 300
      stat        = "Sum"

      dimensions = {
        LoadBalancer = var.alb_arn_suffix
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_unhealthy_hosts" {
  for_each = var.alb_target_group_arn_suffixes

  alarm_name          = "${var.name_prefix}-alb-${each.key}-unhealthy-targets"
  alarm_description   = "ALB target group ${each.key} has unhealthy targets"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = each.value
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_latency" {
  alarm_name          = "${var.name_prefix}-alb-p95-latency-high"
  alarm_description   = "ALB p95 target response time above 2 s"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 3
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }
}

#------------------------------------------------------------------------------
# NLB
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "nlb_unhealthy_hosts" {
  for_each = var.nlb_target_group_arn_suffixes

  alarm_name          = "${var.name_prefix}-nlb-${replace(each.key, "_", "-")}-unhealthy-targets"
  alarm_description   = "NLB target group ${each.key} has unhealthy targets"
  namespace           = "AWS/NetworkELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = each.value
  }
}

#------------------------------------------------------------------------------
# WAF
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  alarm_name          = "${var.name_prefix}-waf-blocked-spike"
  alarm_description   = "WAF blocked more than 1000 requests in 5 minutes (attack or false-positive wave)"
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = var.region
    Rule   = "ALL"
  }
}

#------------------------------------------------------------------------------
# EKS nodes (Container Insights)
#------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "eks_failed_nodes" {
  count = var.enable_container_insights ? 1 : 0

  alarm_name          = "${var.name_prefix}-eks-node-not-ready"
  alarm_description   = "One or more EKS nodes are NotReady for 3 minutes"
  namespace           = "ContainerInsights"
  metric_name         = "cluster_failed_node_count"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    ClusterName = var.eks_cluster_name
  }
}

resource "aws_cloudwatch_metric_alarm" "eks_node_cpu" {
  count = var.enable_container_insights ? 1 : 0

  alarm_name          = "${var.name_prefix}-eks-node-cpu-high"
  alarm_description   = "Average EKS node CPU above 85% for 15 minutes"
  namespace           = "ContainerInsights"
  metric_name         = "node_cpu_utilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.actions
  ok_actions          = local.actions

  dimensions = {
    ClusterName = var.eks_cluster_name
  }
}
