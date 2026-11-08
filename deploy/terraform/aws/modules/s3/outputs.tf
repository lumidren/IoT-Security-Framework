output "artifacts_bucket_name" {
  value = aws_s3_bucket.artifacts.bucket
}

output "artifacts_bucket_arn" {
  value = aws_s3_bucket.artifacts.arn
}

output "artifacts_replica_bucket_name" {
  value = one(aws_s3_bucket.artifacts_replica[*].bucket)
}

output "artifacts_replica_bucket_arn" {
  value = one(aws_s3_bucket.artifacts_replica[*].arn)
}

output "replica_kms_key_arn" {
  value = one(aws_kms_key.replica[*].arn)
}

output "replication_role_arn" {
  value = one(aws_iam_role.replication[*].arn)
}

output "backups_bucket_name" {
  value = aws_s3_bucket.backups.bucket
}

output "backups_bucket_arn" {
  value = aws_s3_bucket.backups.arn
}

output "logs_bucket_name" {
  value = aws_s3_bucket.logs.bucket
}

output "logs_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}
