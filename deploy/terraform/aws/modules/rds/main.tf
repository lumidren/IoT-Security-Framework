locals {
  identifier = "${var.name_prefix}-postgres"
}

#------------------------------------------------------------------------------
# Network
#------------------------------------------------------------------------------

resource "aws_db_subnet_group" "this" {
  name        = local.identifier
  description = "IronMesh PostgreSQL (isolated subnets)"
  subnet_ids  = var.subnet_ids

  tags = {
    Name = local.identifier
  }
}

resource "aws_security_group" "this" {
  name        = "${local.identifier}-db"
  description = "PostgreSQL 5432 from EKS only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.identifier}-db"
  }
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  for_each = toset(var.client_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "PostgreSQL from EKS"
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

#------------------------------------------------------------------------------
# Parameters: TLS mandatory, connection auditing, pgaudit
#------------------------------------------------------------------------------

resource "aws_db_parameter_group" "this" {
  name_prefix = "${local.identifier}-pg16-"
  family      = "postgres16"
  description = "IronMesh PostgreSQL 16: force SSL, connection logging, pgaudit"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  parameter {
    name         = "shared_preload_libraries"
    value        = "pgaudit,pg_stat_statements"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "pgaudit.log"
    value = "role,ddl"
  }

  parameter {
    name  = "pgaudit.log_parameter"
    value = "0"
  }

  lifecycle {
    create_before_destroy = true
  }
}

#------------------------------------------------------------------------------
# Enhanced monitoring role
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

data "aws_partition" "current" {}

resource "aws_iam_role" "monitoring" {
  name               = "${local.identifier}-monitoring"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

#------------------------------------------------------------------------------
# Log groups (pre-created for retention + KMS)
#------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "exports" {
  for_each = toset(["postgresql", "upgrade"])

  name              = "/aws/rds/instance/${local.identifier}/${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

#------------------------------------------------------------------------------
# Instance
#------------------------------------------------------------------------------

resource "aws_db_instance" "this" {
  identifier = local.identifier

  engine                = "postgres"
  engine_version        = var.engine_version
  instance_class        = var.instance_class
  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  publicly_accessible    = false
  multi_az               = var.multi_az
  port                   = 5432

  username                            = var.master_username
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = var.kms_key_arn
  iam_database_authentication_enabled = true
  parameter_group_name                = aws_db_parameter_group.this.name

  backup_retention_period   = var.backup_retention_days
  backup_window             = "02:00-03:00"
  maintenance_window        = "sun:03:30-sun:04:30"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.identifier}-final"

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = var.performance_insights_retention_days
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]

  auto_minor_version_upgrade = true
  apply_immediately          = false
  ca_cert_identifier         = "rds-ca-rsa2048-g1"

  tags = {
    Name = local.identifier
  }

  lifecycle {
    precondition {
      condition     = var.max_allocated_storage_gb >= var.allocated_storage_gb
      error_message = "rds_max_allocated_storage_gb must be >= rds_allocated_storage_gb."
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.exports,
    aws_iam_role_policy_attachment.monitoring,
  ]
}
