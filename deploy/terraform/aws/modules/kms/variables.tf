variable "name_prefix" {
  description = "Resource name prefix (project-environment)."
  type        = string
}

variable "region" {
  description = "AWS region (for service principals and kms:ViaService conditions)."
  type        = string
}

variable "account_id" {
  description = "AWS account id."
  type        = string
}

variable "partition" {
  description = "AWS partition (aws, aws-us-gov, ...)."
  type        = string
}

variable "deletion_window_in_days" {
  description = "KMS key deletion waiting period."
  type        = number
}

variable "admin_principal_arns" {
  description = "IAM principals that may administer keys (never sign/decrypt with CA or firmware keys)."
  type        = list(string)
}

variable "ceremony_role_arn" {
  description = "ARN of the CA ceremony role (root CA signing, firmware key wrapping). May not exist yet."
  type        = string
}

variable "root_ca_require_mfa" {
  description = "Require aws:MultiFactorAuthPresent for kms:Sign with the root CA key."
  type        = bool
}

variable "create_factory_ca_key" {
  description = "Create the Factory CA key."
  type        = bool
}

variable "create_msk_key" {
  description = "Create a CMK for provisioned MSK at-rest encryption."
  type        = bool
}

variable "pki_role_arn" {
  description = "IRSA role ARN of the pki service (signs with Device/Services/Bundle/Factory CA keys)."
  type        = string
}

variable "ota_role_arn" {
  description = "IRSA role ARN of the ota service (unwraps the firmware signing key through Secrets Manager)."
  type        = string
}

variable "backup_role_arn" {
  description = "IRSA role ARN of the backup job (S3 SSE-KMS)."
  type        = string
}

variable "eks_cluster_role_arn" {
  description = "EKS cluster IAM role ARN (secrets envelope encryption)."
  type        = string
}

variable "eks_node_role_arn" {
  description = "EKS node IAM role ARN (EBS volumes)."
  type        = string
}

variable "ebs_csi_role_arn" {
  description = "EBS CSI driver IRSA role ARN (EBS volumes)."
  type        = string
}

variable "s3_replication_role_arn" {
  description = "S3 replication role ARN (decrypts source objects)."
  type        = string
}

variable "secrets_path_prefix" {
  description = "Secrets Manager name prefix, e.g. ironmesh/prod/."
  type        = string
}
