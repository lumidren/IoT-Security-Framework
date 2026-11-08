# Remote state: S3 bucket + DynamoDB lock table, both created once per account by
# ./bootstrap (see README "Apply order"). This is a *partial* configuration: the
# environment-specific values live in environments/<env>.backend.hcl and are passed
# at init time so that no account-specific name is baked into this file:
#
#   terraform init -backend-config=environments/staging.backend.hcl
#
# Switching environments requires `terraform init -reconfigure` (or separate
# working directories / workspaces).
terraform {
  backend "s3" {
    encrypt = true
  }
}
