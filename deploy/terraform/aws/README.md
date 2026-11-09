# IronMesh on AWS (Terraform)

Production infrastructure for the IronMesh control plane: EKS, MSK (or self-hosted Redpanda),
PostgreSQL on RDS, KMS-backed PKI keys, S3 firmware storage with Object Lock, an ALB/WAF edge for
console and APIs and an NLB passthrough edge for MQTT/EST. Everything the Helm chart in
`deploy/helm/ironmesh` needs (IRSA roles, target groups, endpoints) is produced here and handed
over through the `helm_values` output.

Terraform `>= 1.6`, AWS provider `5.x`. Every resource is tagged `Project=IronMesh`,
`Environment=<env>`, `ManagedBy=terraform` through provider `default_tags` (launch-template
instances/volumes receive the same tags explicitly).

## Layout

```
deploy/terraform/aws
├── backend.tf, versions.tf, providers.tf          partial S3 backend, pins, aws/aws.replica/helm/kubernetes
├── variables.tf (validated), locals.tf, main.tf, outputs.tf
├── environments/{staging,prod}.tfvars              environment inputs
├── environments/{staging,prod}.backend.hcl         -backend-config files
├── bootstrap/                                      one-time state bucket + lock table
└── modules/
    ├── network        VPC /16, 3 AZ, public/private/isolated subnets, NAT, flow logs, endpoints
    ├── kms            CA signing keys (P-384/P-256), firmware KEK + Secrets Manager container, data keys
    ├── eks            EKS 1.31, managed node groups, IRSA, KMS secrets encryption, add-ons
    ├── eks-addons     aws-load-balancer-controller, cert-manager, external-dns (helm_release), gp3 SC
    ├── msk            MSK Serverless or provisioned (TLS + IAM), storage autoscaling
    ├── rds            PostgreSQL 16 Multi-AZ, IAM auth, PI, 35 d backups, force_ssl, pgaudit
    ├── s3             firmware (Object Lock, CRR), backups (Object Lock), access logs
    ├── alb            ACM, WAFv2, ALB (console/registry/ota), NLB (mqtt 8883, pki 443/80), Route 53
    ├── observability  SNS topic, CloudWatch alarms (RDS, MSK, ALB/NLB, WAF, EKS nodes)
    └── iam            IRSA roles per service, External Secrets role, CA ceremony role
```

## Prerequisites

* An AWS account with a **public Route 53 hosted zone** for `dns_zone_name` (looked up, never created).
* AWS CLI v2 (used by the Kubernetes/Helm providers for `aws eks get-token`), Terraform `>= 1.6`.
* Nothing is hard-coded to an account: bucket names embed the account id at plan time, principals
  default to the identity running Terraform.

## Apply order

1. **Bootstrap the state backend** (once per account/environment):

   ```bash
   cd deploy/terraform/aws/bootstrap
   terraform init && terraform apply -var environment=staging -var region=eu-west-1
   ```

   Copy the `backend_config` output into `environments/staging.backend.hcl` if you changed the
   defaults (`name_prefix`, region).

2. **Initialise** the root configuration for the environment:

   ```bash
   cd deploy/terraform/aws
   terraform init -backend-config=environments/staging.backend.hcl
   ```

3. **Keys and network first.** KMS key policies reference IAM role *names* (not yet created) and
   the network needs the logs key:

   ```bash
   terraform apply -var-file=environments/staging.tfvars -target=module.kms -target=module.network
   ```

4. **Cluster.** The Kubernetes and Helm providers read the cluster endpoint from `module.eks`, so
   the cluster is created before anything that needs those providers:

   ```bash
   terraform apply -var-file=environments/staging.tfvars -target=module.eks
   ```

5. **Everything else** (add-ons, MSK, RDS, S3, edge, alarms, IAM):

   ```bash
   terraform apply -var-file=environments/staging.tfvars
   ```

   Repeat step 5 without `-target` after any change; the targeted applies are only needed on the
   first run (and after destroying the cluster).

6. **Hand over to Kubernetes:**

   ```bash
   terraform output -raw kubeconfig_command | bash
   terraform output -raw helm_values > ../../helm/ironmesh/values-staging.generated.yaml
   ```

   `values-staging.generated.yaml` carries IRSA role ARNs, target group ARNs, RDS host, Kafka
   bootstrap servers, bucket names and KMS aliases. Layer it on top of `values-staging.yaml`
   (`helm upgrade -f values.yaml -f values-staging.yaml -f values-staging.generated.yaml`).

7. **Post-apply, outside Terraform (by design):**

   * **Databases** `registry`, `ota`, `pki`, `anomaly` and the `*_app` / `ironmesh_backup` roles are
     created by the chart's `dbInit` job using the RDS-managed master secret
     (`rds_master_user_secret_arn`). Terraform has no network path to the database.
   * **Kafka topics** `im.ingest`, `im.auth`, `im.alerts`, `im.audit`, `im.commands`,
     `im.campaigns` are created idempotently by the bridge on boot (`BRIDGE_KAFKA_TOPICS_CREATE`;
     its role has `kafka-cluster:CreateTopic` on exactly those ARNs;
     `auto.create.topics.enable=false`). No `null_resource`, no runner-to-broker network.
   * **CA ceremony**: assume `ceremony_role_arn` (MFA), sign the Device/Services/Factory CA
     certificates with the root key, and wrap the Ed25519 (+ optional ML-DSA-65) firmware signing
     key into `firmware_signing_secret_arn`. See `docs/ops/BACKUP_RESTORE.md` §PKI.
   * **Application secrets** under `ironmesh/<env>/<service>` in Secrets Manager (EMQX API key,
     hook token, PKI/Policy shared tokens, DB passwords when IAM auth is off). The External Secrets
     Operator (installed by platform tooling, role `external_secrets` in `irsa_role_arns`) syncs them.
   * **Alert e-mail subscriptions** must be confirmed by the recipients.

Account-specific principals (`kms_admin_principal_arns`, `ceremony_principal_arns`,
`cluster_admin_principal_arns`) are passed from a git-ignored `environments/<env>.principals.tfvars`
or `TF_VAR_*`; the applying identity is always a KMS administrator and the default ceremony principal.

## Design notes

### Separation of duties in KMS

CA key policies grant **administration** (alias, rotation, policy, deletion scheduling; never
`CreateGrant`) to `kms_admin_principal_arns` and **`kms:Sign`** only to the pki IRSA role (Device,
Services, Bundle, Factory CA) or only to the ceremony role with MFA (Root CA). The account root is
*not* given `kms:*`, so no IAM policy alone can authorise signing; the only path is the key policy.
Principals are expressed as `aws:PrincipalArn` conditions on the account principal, which lets the
key policies reference roles that `module.iam` creates later without a dependency cycle.
Administrators can still re-write a key policy; that action is logged by CloudTrail and should be
alarmed/SCP-restricted at the organisation level.

### Firmware signing: Ed25519 and KMS

The design contract mandates Ed25519 (+ optional ML-DSA-65) firmware signatures. AWS KMS asymmetric
keys support RSA, NIST P-curves, secp256k1 and SM2 — not Ed25519. Rather than weakening the device
verifier to P-256, the Ed25519 private key is generated in the ceremony and stored in Secrets
Manager encrypted under the symmetric CMK `ironmesh-<env>-firmware-kek` (yearly automatic rotation).
Only the ota role (via `kms:ViaService = secretsmanager`) and the ceremony role can decrypt it; the
secret's resource policy denies `GetSecretValue` to everyone else, including administrators and the
External Secrets Operator. Signing happens in the ota process memory and every unwrap is a CloudTrail
event. Signing-key rotation = add a new public key to the bundle's `fw_signing_pubkeys`, wrap the new
private key, retire the old one after the fleet has received the new bundle.

The PKI bundle key (`X-IronMesh-Bundle`) is Ed25519 (COSE alg -8, kid `pki-bundle`), which KMS cannot hold, so it follows the firmware-key pattern: the seed lives in Secrets Manager (`<prefix>pki/bundle-signing-key`) encrypted under the symmetric CMK `bundle_kek` (`alias/<prefix>-bundle-kek`), readable only by the pki IRSA role and the ceremony role and decryptable only through Secrets Manager (`kms:ViaService`). The External Secrets role is explicitly denied, so the seed is never materialised as a Kubernetes Secret. The pki service reads it directly at start: `helm_values` sets `PKI_BUNDLE_KEY_SECRET_ARN` (and `PKI_DB_IAM_AUTH`/`PKI_DB_IAM_REGION` for the `pki_app` RDS IAM login).

### Kafka

`kafka_mode` selects `msk-provisioned` (TLS in transit, CMK at rest, IAM auth, Prometheus JMX/node
exporters, storage autoscaling), `msk-serverless` (IAM auth, AWS-owned key) or `redpanda` (no MSK
resources; the chart deploys the Redpanda dependency on EKS and the Kafka IAM statements are
skipped).

### Edge

TLS for MQTT and EST terminates **inside the cluster** (EMQX / pki) because both are mutual-TLS
protocols; the NLB is pure TCP passthrough with client IP preservation. The ALB terminates TLS 1.3
for console/registry/ota with the ACM wildcard and is protected by WAFv2 (Common, KnownBadInputs,
SQLi, IP reputation, 2 000 req/5 min/IP rate rule; `SizeRestrictions_BODY` is in count mode because
firmware uploads exceed the 8 KiB inspection window). Pods are attached with `TargetGroupBinding`
objects from the Helm chart; the security group rules from the load balancers to the cluster
security group are created here, so the chart leaves `TargetGroupBinding.networking` unset.

### Data protection

* RDS: CMK-encrypted storage, PI and master secret; `rds.force_ssl=1`, `log_connections`,
  pgaudit; IAM authentication; 35-day PITR; deletion protection; final snapshot.
* S3 firmware: versioning, SSE-KMS (bucket policy denies any other key or unencrypted PUT), Object
  Lock GOVERNANCE default retention, STANDARD_IA after 90 days, cross-region replication with RTC.
* S3 backups: same controls, 35-day GOVERNANCE lock, Glacier IR after 90 days.
* Logs bucket is SSE-S3 because ALB access-log delivery does not support SSE-KMS.

## Cost notes (eu-west-1 list prices, on-demand, approximate monthly)

| Component                                   | prod.tfvars                     | staging.tfvars                 |
|---------------------------------------------|---------------------------------|--------------------------------|
| EKS control plane                           | $73                             | $73                            |
| Nodes (3× m7i.xlarge + 3× c7i.xlarge / 3× m7i.large) | ~$830                  | ~$220                          |
| NAT gateways (3 / 1) + processing           | ~$100 + $0.045/GB               | ~$33 + $0.045/GB               |
| Interface endpoints (6 services × 3 AZ)     | ~$145                           | ~$145                          |
| RDS (db.r6g.large Multi-AZ / db.t4g.medium) | ~$430 + storage/backups         | ~$60                           |
| Kafka (MSK provisioned 3× m7g.large + 1.5 TB / MSK Serverless) | ~$630      | ~$550 + partition hours        |
| ALB + NLB + WAF                             | ~$55 + LCU/request charges      | ~$55                           |
| KMS (12 CMKs) + Secrets Manager             | ~$20                            | ~$20                           |
| CloudWatch (logs, Container Insights, alarms) | $0.57/GB ingested + ~$100      | $0.57/GB ingested              |
| S3 + replication                            | storage + $0.02/GB replicated   | storage                        |
| **Order of magnitude**                      | **~$2.5–3k**                    | **~$1.1–1.3k**                 |

Cheapest meaningful staging: `kafka_mode = "redpanda"` (drops ~$550), `vpc_interface_endpoints = []`
(drops ~$145, traffic then flows through NAT), `az_count = 2`. The Serverless choice in
`staging.tfvars` is deliberate: it exercises the same IAM-auth code path as prod.

## Destroying

`terraform destroy` is blocked by design in several places: RDS deletion protection
(`rds_deletion_protection = false` first), load balancer deletion protection, Object Lock (locked
object versions cannot be deleted until retention expires; empty the buckets with
`s3:BypassGovernanceRetention` from a break-glass role), and KMS deletion windows (7–30 days).
Destroy Helm releases (`helm uninstall ironmesh`) before destroying the cluster so that
TargetGroupBindings deregister cleanly.

## Validation

This directory is validated in CI with `terraform fmt -check`, `terraform validate` (per module
and root, with `-backend=false`), `tflint` and `checkov`. Locally, without Terraform installed,
`python -m hcl2` parses every file and the repository's validation script cross-checks module
inputs against module variables and outputs.
