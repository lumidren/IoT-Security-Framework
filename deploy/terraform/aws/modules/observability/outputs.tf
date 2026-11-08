output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "application_log_group_name" {
  value = aws_cloudwatch_log_group.application.name
}

output "alarm_names" {
  value = concat(
    [
      aws_cloudwatch_metric_alarm.rds_cpu.alarm_name,
      aws_cloudwatch_metric_alarm.rds_storage.alarm_name,
      aws_cloudwatch_metric_alarm.rds_memory.alarm_name,
      aws_cloudwatch_metric_alarm.alb_5xx_ratio.alarm_name,
      aws_cloudwatch_metric_alarm.alb_latency.alarm_name,
      aws_cloudwatch_metric_alarm.waf_blocked.alarm_name,
    ],
    [for a in aws_cloudwatch_metric_alarm.alb_unhealthy_hosts : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.nlb_unhealthy_hosts : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.msk_disk : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.msk_offline_partitions : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.msk_controller : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.eks_failed_nodes : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.eks_node_cpu : a.alarm_name],
  )
}
