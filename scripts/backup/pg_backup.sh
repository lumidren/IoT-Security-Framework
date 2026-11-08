#!/usr/bin/env bash
# pg_backup.sh - logical backups of the IronMesh databases to S3 (SSE-KMS) with retention.
#
# For each database in PG_DATABASES: pg_dump (custom format), SHA-256, a JSON manifest with
# per-table row counts (used by pg_restore_test.sh), upload with SSE-KMS, then prune dumps
# older than RETENTION_DAYS (Object Lock still protects anything inside the lock window).
#
# Environment (defaults in parentheses):
#   AWS_REGION            region of the bucket and the RDS instance (eu-west-1)
#   BACKUP_BUCKET         destination bucket                                (required)
#   BACKUP_PREFIX         key prefix                                         (postgres)
#   BACKUP_KMS_KEY_ID     KMS key id/ARN/alias for SSE-KMS                    (alias/ironmesh-prod-s3)
#   PGHOST / PGPORT       database endpoint                                  (required / 5432)
#   PGUSER                backup role                                        (ironmesh_backup)
#   PG_IAM_AUTH           true = password from `aws rds generate-db-auth-token` (true)
#   PGPASSWORD            used when PG_IAM_AUTH=false
#   PGSSLMODE             libpq sslmode                                      (verify-full)
#   PGSSLROOTCERT         CA bundle for RDS                                  (/etc/ssl/certs/ca-certificates.crt)
#   PG_DATABASES          space separated list                               (registry ota pki anomaly)
#   RETENTION_DAYS        prune dumps older than this                        (35)
#   PRUNE_ENABLED         false disables pruning                             (true)
#   WORK_DIR              scratch directory                                  (mktemp)
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-1}"
BACKUP_BUCKET="${BACKUP_BUCKET:?BACKUP_BUCKET is required}"
BACKUP_PREFIX="${BACKUP_PREFIX:-postgres}"
BACKUP_KMS_KEY_ID="${BACKUP_KMS_KEY_ID:-alias/ironmesh-prod-s3}"
PGHOST="${PGHOST:?PGHOST is required}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-ironmesh_backup}"
PG_IAM_AUTH="${PG_IAM_AUTH:-true}"
PGSSLMODE="${PGSSLMODE:-verify-full}"
PGSSLROOTCERT="${PGSSLROOTCERT:-/etc/ssl/certs/ca-certificates.crt}"
PG_DATABASES="${PG_DATABASES:-registry ota pki anomaly}"
RETENTION_DAYS="${RETENTION_DAYS:-35}"
PRUNE_ENABLED="${PRUNE_ENABLED:-true}"
export AWS_REGION PGHOST PGPORT PGUSER PGSSLMODE PGSSLROOTCERT

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

for tool in aws pg_dump psql sha256sum jq; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing dependency: ${tool}"
done

WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

if [[ "${PG_IAM_AUTH}" == "true" ]]; then
  PGPASSWORD="$(aws rds generate-db-auth-token --hostname "${PGHOST}" --port "${PGPORT}" --username "${PGUSER}" --region "${AWS_REGION}")"
  export PGPASSWORD
else
  : "${PGPASSWORD:?PGPASSWORD is required when PG_IAM_AUTH=false}"
  export PGPASSWORD
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
failures=0

row_counts_json() {
  # Exact row counts of every user table in the database, as a JSON object {schema.table: n}.
  local db="$1"
  psql -X -At -v ON_ERROR_STOP=1 -d "${db}" <<'SQL' | jq -Rs 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): (.[1] | tonumber)}) | add // {}'
SELECT format('%s.%s', n.nspname, c.relname) || E'\t' ||
       (xpath('/row/cnt/text()', query_to_xml(format('SELECT count(*) AS cnt FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1;
SQL
}

backup_database() {
  local db="$1"
  local dump="${WORK_DIR}/${db}-${timestamp}.dump"
  local manifest="${WORK_DIR}/${db}-${timestamp}.manifest.json"
  local key_base="${BACKUP_PREFIX}/${db}/${timestamp}"

  log "dumping ${db}"
  pg_dump --format=custom --compress=6 --no-owner --no-privileges --serializable-deferrable \
    --dbname="${db}" --file="${dump}"

  local sha
  sha="$(sha256sum "${dump}" | awk '{print $1}')"
  local size
  size="$(stat -c %s "${dump}" 2>/dev/null || stat -f %z "${dump}")"
  local counts
  counts="$(row_counts_json "${db}")"
  local server_version
  server_version="$(psql -X -At -d "${db}" -c 'SHOW server_version')"

  jq -n \
    --arg database "${db}" \
    --arg taken_at "${timestamp}" \
    --arg host "${PGHOST}" \
    --arg sha256 "${sha}" \
    --argjson size "${size}" \
    --arg server_version "${server_version}" \
    --arg key "${key_base}.dump" \
    --argjson tables "${counts}" \
    '{database: $database, taken_at: $taken_at, host: $host, sha256: $sha256, size_bytes: $size, server_version: $server_version, s3_key: $key, format: "pg_dump custom", tables: $tables}' \
    > "${manifest}"

  log "uploading ${db} (${size} bytes, sha256 ${sha})"
  aws s3 cp "${dump}" "s3://${BACKUP_BUCKET}/${key_base}.dump" \
    --sse aws:kms --sse-kms-key-id "${BACKUP_KMS_KEY_ID}" --only-show-errors \
    --metadata "sha256=${sha},database=${db},taken_at=${timestamp}"
  aws s3 cp "${manifest}" "s3://${BACKUP_BUCKET}/${key_base}.manifest.json" \
    --sse aws:kms --sse-kms-key-id "${BACKUP_KMS_KEY_ID}" --only-show-errors \
    --content-type application/json
  # Stable pointer to the newest manifest for the restore test.
  aws s3 cp "${manifest}" "s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/${db}/latest.manifest.json" \
    --sse aws:kms --sse-kms-key-id "${BACKUP_KMS_KEY_ID}" --only-show-errors \
    --content-type application/json
  rm -f "${dump}"
}

prune_database() {
  local db="$1"
  local cutoff
  cutoff="$(date -u -d "-${RETENTION_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v "-${RETENTION_DAYS}d" +%Y-%m-%dT%H:%M:%SZ)"
  local keys
  keys="$(aws s3api list-objects-v2 --bucket "${BACKUP_BUCKET}" --prefix "${BACKUP_PREFIX}/${db}/" \
    --query "Contents[?LastModified<'${cutoff}' && !ends_with(Key, 'latest.manifest.json')].Key" --output text)"
  if [[ -z "${keys}" || "${keys}" == "None" ]]; then
    log "prune ${db}: nothing older than ${RETENTION_DAYS} days"
    return 0
  fi
  local key
  while read -r key; do
    [[ -z "${key}" ]] && continue
    # Governance-locked versions are rejected here on purpose; lifecycle expires them later.
    if aws s3api delete-object --bucket "${BACKUP_BUCKET}" --key "${key}" >/dev/null 2>&1; then
      log "pruned ${key}"
    else
      log "prune skipped (locked or denied): ${key}"
    fi
  done <<< "$(printf '%s\n' "${keys}" | tr '\t' '\n')"
}

for db in ${PG_DATABASES}; do
  if backup_database "${db}"; then
    if [[ "${PRUNE_ENABLED}" == "true" ]]; then
      prune_database "${db}" || log "prune failed for ${db} (continuing)"
    fi
  else
    log "backup FAILED for ${db}"
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  die "${failures} database backup(s) failed"
fi
log "all backups complete: ${PG_DATABASES} -> s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/"
