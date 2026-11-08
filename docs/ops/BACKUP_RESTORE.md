# Backup and restore

Operational runbook for the IronMesh control plane on AWS (`deploy/terraform/aws`). Scripts live
in `scripts/backup/` and run from CI (nightly) or from an operator workstation with the `backup`
IRSA role / an equivalent profile. Nothing in this document requires a private key to leave AWS
KMS.

## Objectives

| Data set                           | RPO       | RTO     | Mechanism                                                       |
|------------------------------------|-----------|---------|-----------------------------------------------------------------|
| PostgreSQL (`registry`, `ota`, `pki`, `anomaly`) | 5 min (PITR) / 24 h (dumps) | 1 h | RDS automated backups 35 d + nightly logical dumps to S3 |
| Firmware artifacts                 | 15 min    | 1 h     | S3 versioning + Object Lock + cross-region replication (RTC)    |
| PKI metadata (certificates, revocations, CRL number, tenant policies) | 24 h | 2 h | included in the `pki` dump + daily PKI export |
| CA private keys                    | n/a       | n/a     | never exported; KMS multi-AZ durability + root quorum procedure |
| Firmware signing keys (Ed25519 / ML-DSA) | n/a | 4 h     | Secrets Manager (KMS-wrapped) replicated to the second region   |
| Kafka topics                       | best effort | 30 min | not backed up: ingest is re-derivable from devices (`seq`, offline ring buffers); topics are recreated by the bridge |
| Kubernetes state                   | n/a       | 1 h     | Git (Helm values, Terraform) + ESO re-sync of secrets           |

## What runs when

| Job                                   | Schedule          | Script                           | Output / check                                      |
|---------------------------------------|-------------------|----------------------------------|-----------------------------------------------------|
| Logical dumps                         | daily 02:30 UTC   | `pg_backup.sh`                   | `s3://<backups>/postgres/<db>/<ts>.dump` + manifest  |
| Restore drill                         | daily 04:00 UTC   | `pg_restore_test.sh`             | restores the latest dump into a scratch DB, row counts must match the manifest, `SELECT 1` on key tables; non-zero exit fails the CI job |
| PKI export                            | daily 03:00 UTC   | `pki_backup.sh`                  | `s3://<backups>/pki/<ts>/` key metadata, public keys, CA chain, CRL, quorum inventory |
| Firmware replication + integrity      | daily 03:30 UTC   | `firmware_backup.sh`             | replication status, replica object presence, SHA-256 of recent artifacts vs the OTA database |
| RDS snapshots                         | daily (RDS)       | Terraform `backup_window`        | 35-day retention, PITR                              |

All objects land in the backups bucket with `--sse aws:kms --sse-kms-key-id <s3 key>` (the bucket
policy rejects anything else), under a 35-day GOVERNANCE Object Lock, lifecycle to Glacier IR
after 90 days and expiry after `backup_retention_days` (400 in prod).

Environment for the scripts (all have defaults, see each header): `AWS_REGION`, `BACKUP_BUCKET`,
`BACKUP_KMS_KEY_ID`, `PGHOST`/`PGPORT`/`PGUSER`, `PG_IAM_AUTH` (use `aws rds generate-db-auth-token`
instead of `PGPASSWORD`), `PG_DATABASES`, `RETENTION_DAYS`, `FIRMWARE_BUCKET`,
`FIRMWARE_REPLICA_BUCKET`, `OTA_DB_NAME`, `KMS_ALIAS_PREFIX`, `QUORUM_INVENTORY_SECRET`.

## Restore procedures

### A. PostgreSQL point-in-time (preferred, data loss ≤ 5 min)

1. `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier ironmesh-prod-postgres --target-db-instance-identifier ironmesh-prod-postgres-pitr --restore-time <RFC3339> --db-subnet-group-name ironmesh-prod-postgres --vpc-security-group-ids <sg> --db-parameter-group-name <pg> --no-publicly-accessible`
2. Verify with `pg_restore_test.sh`-style checks against the new instance (`PGHOST` override).
3. Repoint the Helm value `database.host` (or swap the Route 53 CNAME if one is used), run
   `helm upgrade`, then let the db-init job confirm roles. IAM authentication keeps working because
   `rds-db:connect` ARNs are tied to the *new* DbiResourceId: update `module.rds` in Terraform by
   importing the restored instance or by `terraform apply` with the new identifier.

### B. PostgreSQL from a logical dump (cross-account / corruption / selective)

```bash
export PGHOST=<target> PGUSER=ironmesh_admin PGSSLMODE=verify-full
aws s3 cp "s3://$BACKUP_BUCKET/postgres/registry/<ts>.dump" /tmp/registry.dump
sha256sum -c <(aws s3 cp "s3://$BACKUP_BUCKET/postgres/registry/<ts>.manifest.json" - | jq -r '.sha256 + "  /tmp/registry.dump"')
createdb registry_restore
pg_restore --no-owner --no-privileges --role=registry_owner -d registry_restore /tmp/registry.dump
```

Then re-apply ownership (`REASSIGN OWNED BY ironmesh_admin TO registry_owner`) and grants from the
db-init job, and swap database names during a maintenance window.

### C. Firmware artifacts

* Accidental overwrite/delete: Object Lock blocks deletes inside the retention window; restore a
  previous version with `aws s3api copy-object --copy-source "<bucket>/<key>?versionId=<id>"`.
* Regional outage: the replica bucket in `replica_region` holds every object (RTC ≤ 15 min).
  Switch `OTA_ARTIFACT_BUCKET` to the replica (and `OTA_S3_KMS_KEY_ARN` to the replica key) with a
  `helm upgrade`; devices download via the OTA service, so no device-side change is needed.
* Integrity: `firmware_backup.sh` recomputes SHA-256 against `sha256_hex` in the OTA database and
  exits non-zero on mismatch; a mismatch is an incident (immutable artifacts should never change).

### D. PKI

CA private keys live only in KMS. Recovery scenarios:

1. **Service outage / cluster loss**: redeploy from Git; keys and the `pki` database are intact.
2. **`pki` database loss**: restore via A or B. Certificates issued after the restore point are
   unknown to OCSP/CRL; devices with such certificates still authenticate (chain validation at the
   broker) and renew normally at 50% lifetime (14 d max window). Revocations issued in the lost
   window must be replayed from the audit trail (`im.audit`, console audit export).
3. **Compromised intermediate (Device/Services CA)**: ceremony role creates a new CA key, signs it
   with the root key (`kms:Sign` by the ceremony role with MFA), updates the KMS alias, pki rolls
   the issuer; EMQX trusts both bundles during the 14-day rollover; old CA goes to the CRL/bundle
   `ca_pins` update.
4. **Root CA**: the root key is a KMS key (`ECC_NIST_P384`) that cannot be exported. The "quorum" is
   procedural: the ceremony role can only be assumed by M-of-N named principals with MFA, and the
   inventory of those principals, their hardware tokens and attestations is kept in Secrets
   Manager (`ironmesh/<env>/pki/root-ca-quorum-inventory`) and exported daily by `pki_backup.sh`.
   Losing the KMS key (account loss) means re-issuing the root and re-flashing the bundle public
   key on devices; this is the documented disaster scenario and the reason the account is covered by
   AWS Backup/Organizations controls outside this repository.

`pki_backup.sh` exports, for every CA key: `DescribeKey`, `GetKeyPolicy`, `GetKeyRotationStatus`,
`ListGrants`, the public key (PEM) and alias; plus the CA chain and CRL fetched from the PKI, and
the quorum inventory. Private keys are **never** part of the export.

### E. Firmware signing keys

The Ed25519/ML-DSA private keys are stored in Secrets Manager encrypted with the
`ironmesh-<env>-firmware-kek` CMK and replicated to the second region
(`aws secretsmanager replicate-secret-to-regions`). `pki_backup.sh` records the replication status.
Loss of the secret means a new signing key: add its public key to the bundle
(`fw_signing_pubkeys`) through the PKI, wait for the fleet to receive the new bundle, then sign
with the new key.

## Verification cadence

* Nightly: `pg_restore_test.sh` (CI job fails loudly), `firmware_backup.sh` checksums.
* Monthly: restore drill of procedure A into an isolated VPC; attach a console to it and run the
  conformance suite against the restored registry/ota/pki.
* Quarterly: tabletop of procedure D.3 (intermediate CA rotation) in staging, end to end.

## Where to look when something fails

| Symptom                                   | First checks                                                                 |
|-------------------------------------------|-------------------------------------------------------------------------------|
| `pg_backup.sh` cannot connect             | IAM token expired (15 min), `rds-db:connect` ARN for `ironmesh_backup`, SG    |
| upload denied                             | missing `--sse aws:kms` / wrong key (bucket policy `DenyWrongKmsKey`)         |
| restore test row-count mismatch           | dump taken mid-migration; compare manifest `taken_at` with migration history; rerun |
| replication `PENDING`/`FAILED`            | replication role policy, replica key policy, RTC metrics in CloudWatch        |
| checksum mismatch                         | treat as integrity incident: quarantine the artifact (halt campaigns), compare versions |
