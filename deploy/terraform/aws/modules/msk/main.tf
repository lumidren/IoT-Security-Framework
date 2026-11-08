#------------------------------------------------------------------------------
# Kafka on MSK
#
# Topics (im.ingest, im.auth, im.alerts, im.audit; DESIGN_CONTRACT.md §7) are deliberately
# NOT created here: there is no MSK topic resource and a null_resource/local-exec would need
# network access to the brokers from the Terraform runner. The bridge service creates the
# topics idempotently on boot through the Kafka admin API; its IRSA role carries
# kafka-cluster:CreateTopic on exactly those four topic ARNs (modules/iam). Partition and
# replication settings come from the bridge environment (BRIDGE_KAFKA_TOPIC_PARTITIONS /
# BRIDGE_KAFKA_TOPIC_REPLICATION) and auto.create.topics.enable is forced off.
#------------------------------------------------------------------------------

locals {
  provisioned        = var.mode == "msk-provisioned"
  cluster_name       = "${var.name_prefix}-kafka"
  replication_factor = min(3, var.broker_count)
  min_insync         = max(1, min(2, var.broker_count - 1))
  cluster_arn        = local.provisioned ? aws_msk_cluster.this[0].arn : aws_msk_serverless_cluster.this[0].arn
}

#------------------------------------------------------------------------------
# Network
#------------------------------------------------------------------------------

resource "aws_security_group" "this" {
  name        = "${local.cluster_name}-brokers"
  description = "MSK brokers: SASL/IAM 9098 and TLS 9094 from EKS only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.cluster_name}-brokers"
  }
}

resource "aws_vpc_security_group_ingress_rule" "iam" {
  for_each = toset(var.client_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "Kafka SASL/IAM from EKS"
  referenced_security_group_id = each.value
  from_port                    = 9098
  to_port                      = 9098
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "tls" {
  for_each = toset(var.client_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "Kafka TLS from EKS"
  referenced_security_group_id = each.value
  from_port                    = 9094
  to_port                      = 9094
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "intra" {
  security_group_id            = aws_security_group.this.id
  description                  = "Broker to broker"
  referenced_security_group_id = aws_security_group.this.id
  ip_protocol                  = "-1"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.this.id
  description       = "Broker egress"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

#------------------------------------------------------------------------------
# Serverless
#------------------------------------------------------------------------------

resource "aws_msk_serverless_cluster" "this" {
  count = local.provisioned ? 0 : 1

  cluster_name = local.cluster_name

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  client_authentication {
    sasl {
      iam {
        enabled = true
      }
    }
  }

  tags = {
    Name = local.cluster_name
  }
}

#------------------------------------------------------------------------------
# Provisioned
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "broker" {
  count = local.provisioned ? 1 : 0

  name              = "/ironmesh/${var.name_prefix}/msk-broker"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_msk_configuration" "this" {
  count = local.provisioned ? 1 : 0

  name           = "${local.cluster_name}-${replace(var.kafka_version, ".", "-")}"
  kafka_versions = [var.kafka_version]

  server_properties = <<-PROPERTIES
    auto.create.topics.enable=false
    allow.everyone.if.no.acl.found=false
    default.replication.factor=${local.replication_factor}
    min.insync.replicas=${local.min_insync}
    num.partitions=12
    log.retention.hours=168
    unclean.leader.election.enable=false
    message.max.bytes=1048588
  PROPERTIES

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_msk_cluster" "this" {
  count = local.provisioned ? 1 : 0

  cluster_name           = local.cluster_name
  kafka_version          = var.kafka_version
  number_of_broker_nodes = var.broker_count
  enhanced_monitoring    = "PER_TOPIC_PER_PARTITION"

  broker_node_group_info {
    instance_type   = var.broker_instance_type
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.this.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.ebs_volume_size_gb
      }
    }

    connectivity_info {
      public_access {
        type = "DISABLED"
      }
    }
  }

  client_authentication {
    unauthenticated = false

    sasl {
      iam = true
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = var.kms_key_arn

    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.this[0].arn
    revision = aws_msk_configuration.this[0].latest_revision
  }

  open_monitoring {
    prometheus {
      jmx_exporter {
        enabled_in_broker = true
      }

      node_exporter {
        enabled_in_broker = true
      }
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.broker[0].name
      }
    }
  }

  tags = {
    Name = local.cluster_name
  }

  lifecycle {
    # Storage auto-scaling (below) changes the volume size outside Terraform.
    ignore_changes = [broker_node_group_info[0].storage_info[0].ebs_storage_info[0].volume_size]

    precondition {
      condition     = var.kms_key_arn != null
      error_message = "A KMS key ARN is required for provisioned MSK at-rest encryption."
    }
  }
}

resource "aws_appautoscaling_target" "storage" {
  count = local.provisioned ? 1 : 0

  max_capacity       = var.ebs_volume_size_gb * 4
  min_capacity       = 1
  resource_id        = aws_msk_cluster.this[0].arn
  scalable_dimension = "kafka:broker-storage:VolumeSize"
  service_namespace  = "kafka"
}

resource "aws_appautoscaling_policy" "storage" {
  count = local.provisioned ? 1 : 0

  name               = "${local.cluster_name}-storage"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.storage[0].resource_id
  scalable_dimension = aws_appautoscaling_target.storage[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.storage[0].service_namespace

  target_tracking_scaling_policy_configuration {
    disable_scale_in = true
    target_value     = 70

    predefined_metric_specification {
      predefined_metric_type = "KafkaBrokerStorageUtilization"
    }
  }
}

#------------------------------------------------------------------------------
# Connection details (works for both modes)
#------------------------------------------------------------------------------

data "aws_msk_bootstrap_brokers" "this" {
  cluster_arn = local.cluster_arn
}
