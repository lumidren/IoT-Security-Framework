# terraform init -backend-config=environments/prod.backend.hcl
# Bucket and table are created by ./bootstrap (names must match its outputs).
bucket         = "ironmesh-tfstate-prod"
key            = "aws/prod/terraform.tfstate"
region         = "eu-west-1"
dynamodb_table = "ironmesh-tfstate-lock-prod"
encrypt        = true
