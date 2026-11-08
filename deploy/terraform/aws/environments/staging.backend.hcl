# terraform init -backend-config=environments/staging.backend.hcl
# Bucket and table are created by ./bootstrap (names must match its outputs).
bucket         = "ironmesh-tfstate-staging"
key            = "aws/staging/terraform.tfstate"
region         = "eu-west-1"
dynamodb_table = "ironmesh-tfstate-lock-staging"
encrypt        = true
