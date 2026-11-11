#!/usr/bin/env bash
# pg_restore_test.sh - nightly restore drill for the IronMesh database dumps.
#
# For each database: fetch latest.manifest.json, download the dump it points at, verify the
# SHA-256, restore it into a scratch database on RESTORE_PGHOST, compare every table's row
# count with the manifest, run `SELECT 1` against the key tables, then drop the scratch
# database. Any mismatch or error exits non-zero so the CI job fails.
#
# Environment (defaults in parentheses):
#   AWS_REGION               (eu-west-1)
#   BACKUP_BUCKET            source bucket                                    (required)
#   BACKUP_PREFIX            key prefix                                       (postgres)
#   RESTORE_PGHOST           scratch PostgreSQL endpoint                      (required)
#   RESTORE_PGPORT           (5432)
#   RESTORE_PGUSER           role allowed to CREATE DATABASE                  (ironmesh_admin)
#   RESTORE_PG_IAM_AUTH      true = IAM auth token                            (false)
#   RESTORE_PGPASSWORD       password when IAM auth is off
#   PGSSLMODE / PGSSLROOTCERT                                                 (verify-full / system bundle)
#   PG_DATABASES             (registry ota pki anomaly)
#   KEY_TABLES_<DB>          space separated tables that must answer SELECT 1 (contract defaults below)
#   KEEP_SCRATCH             true keeps the scratch databases for inspection   (false)
#   MAX_DUMP_AGE_HOURS       fail if the latest dump is older than this        (30)
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-1}"
BACKUP_BUCKET="${BACKUP_BUCKET:?BACKUP_BUCKET is required}"
BACKUP_PREFIX="${BACKUP_PREFIX:-postgres}"
RESTORE_PGHOST="${RESTORE_PGHOST:?RESTORE_PGHOST is required}"
RESTORE_PGPORT="${RESTORE_PGPORT:-5432}"
RESTORE_PGUSER="${RESTORE_PGUSER:-ironmesh_admin}"
RESTORE_PG_IAM_AUTH="${RESTORE_PG_IAM_AUTH:-false}"
PGSSLMODE="${PGSSLMODE:-verify-full}"
PGSSLROOTCERT="${PGSSLROOTCERT:-/etc/ssl/certs/ca-certificates.crt}"
PG_DATABASES="${PG_DATABASES:-registry ota pki anomaly}"
KEEP_SCRATCH="${KEEP_SCRATCH:-false}"
MAX_DUMP_AGE_HOURS="${MAX_DUMP_AGE_HOURS:-30}"

# Key tables per database (services' schemas; override with KEY_TABLES_<DB>).
KEY_TABLES_REGISTRY="${KEY_TABLES_REGISTRY:-tenants devices audit_events}"
KEY_TABLES_OTA="${KEY_TABLES_OTA:-firmware campaigns}"
KEY_TABLES_PKI="${KEY_TABLES_PKI:-certificates revocations crl_counter tenant_policies}"
KEY_TABLES_ANOMALY="${KEY_TABLES_ANOMALY:-alerts}"

export AWS_REGION PGSSLMODE PGSSLROOTCERT
export PGHOST="${RESTORE_PGHOST}" PGPORT="${RESTORE_PGPORT}" PGUSER="${RESTORE_PGUSER}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

for tool in aws pg_restore psql sha256sum jq; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing dependency: ${tool}"
done

if [[ "${RESTORE_PG_IAM_AUTH}" == "true" ]]; then
  PGPASSWORD="$(aws rds generate-db-auth-token --hostname "${RESTORE_PGHOST}" --port "${RESTORE_PGPORT}" --username "${RESTORE_PGUSER}" --region "${AWS_REGION}")"
else
  PGPASSWORD="${RESTORE_PGPASSWORD:?RESTORE_PGPASSWORD is required when RESTORE_PG_IAM_AUTH=false}"
fi
export PGPASSWORD

WORK_DIR="$(mktemp -d)"
SCRATCH_DBS=()
cleanup() {
  if [[ "${KEEP_SCRATCH}" != "true" ]]; then
    local scratch
    for scratch in "${SCRATCH_DBS[@]:-}"; do
      [[ -z "${scratch}" ]] && continue
      psql -X -q -d postgres -c "DROP DATABASE IF EXISTS \"${scratch}\" WITH (FORCE)" >/dev/null 2>&1 || true
    done
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

run_id="$(date -u +%Y%m%d%H%M%S)"
failures=0

check_age() {
  local taken_at="$1" db="$2"
  local taken_epoch now_epoch age_hours
  taken_epoch="$(date -u -d "${taken_at:0:4}-${taken_at:4:2}-${taken_at:6:2}T${taken_at:9:2}:${taken_at:11:2}:${taken_at:13:2}Z" +%s 2>/dev/null \
    || date -u -j -f %Y%m%dT%H%M%SZ "${taken_at}" +%s)"
  now_epoch="$(date -u +%s)"
  age_hours=$(( (now_epoch - taken_epoch) / 3600 ))
  if (( age_hours > MAX_DUMP_AGE_HOURS )); then
    log "${db}: latest dump is ${age_hours}h old (limit ${MAX_DUMP_AGE_HOURS}h)"
    return 1
  fi
  log "${db}: dump age ${age_hours}h"
}

restore_test() {
  local db="$1"
  local manifest="${WORK_DIR}/${db}.manifest.json"
  local dump="${WORK_DIR}/${db}.dump"
  local scratch="restoretest_${db}_${run_id}"

  log "${db}: fetching latest manifest"
  aws s3 cp "s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/${db}/latest.manifest.json" "${manifest}" --only-show-errors

  local key expected_sha taken_at
  key="$(jq -r '.s3_key' "${manifest}")"
  expected_sha="$(jq -r '.sha256' "${manifest}")"
  taken_at="$(jq -r '.taken_at' "${manifest}")"
  [[ -n "${key}" && "${key}" != "null" ]] || { log "${db}: manifest has no s3_key"; return 1; }
  check_age "${taken_at}" "${db}" || return 1

  log "${db}: downloading ${key}"
  aws s3 cp "s3://${BACKUP_BUCKET}/${key}" "${dump}" --only-show-errors
  local actual_sha
  actual_sha="$(sha256sum "${dump}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    log "${db}: SHA-256 mismatch (manifest ${expected_sha}, file ${actual_sha})"
    return 1
  fi

  log "${db}: restoring into ${scratch}"
  psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE DATABASE \"${scratch}\" TEMPLATE template0 ENCODING 'UTF8'"
  SCRATCH_DBS+=("${scratch}")
  pg_restore --no-owner --no-privileges --exit-on-error --jobs=4 --dbname="${scratch}" "${dump}"

  local mismatches=0
  local table expected actual
  while IFS=$'\t' read -r table expected; do
    [[ -z "${table}" ]] && continue
    actual="$(psql -X -At -v ON_ERROR_STOP=1 -d "${scratch}" -c "SELECT count(*) FROM ${table}")"
    if [[ "${actual}" != "${expected}" ]]; then
      log "${db}: row count mismatch in ${table}: manifest ${expected}, restored ${actual}"
      mismatches=$((mismatches + 1))
    fi
  done < <(jq -r '.tables | to_entries[] | "\(.key)\t\(.value)"' "${manifest}")
  local table_count
  table_count="$(jq -r '.tables | length' "${manifest}")"
  log "${db}: compared ${table_count} table row counts, ${mismatches} mismatch(es)"

  local key_tables_var="KEY_TABLES_$(printf '%s' "${db}" | tr '[:lower:]' '[:upper:]')"
  local key_tables="${!key_tables_var:-}"
  local missing=0
  for table in ${key_tables}; do
    if psql -X -At -v ON_ERROR_STOP=1 -d "${scratch}" -c "SELECT 1 FROM ${table} LIMIT 1" >/dev/null 2>&1; then
      log "${db}: SELECT 1 FROM ${table} ok"
    else
      log "${db}: key table ${table} missing or unreadable"
      missing=$((missing + 1))
    fi
  done

  if (( mismatches > 0 || missing > 0 )); then
    return 1
  fi
  rm -f "${dump}"
  log "${db}: restore test passed"
}

for db in ${PG_DATABASES}; do
  if ! restore_test "${db}"; then
    log "${db}: restore test FAILED"
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  die "${failures} restore test(s) failed"
fi
log "all restore tests passed for: ${PG_DATABASES}"
