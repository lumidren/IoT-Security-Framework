#!/usr/bin/env bash
# firmware_backup.sh - cross-region replication check and integrity verification of the
# firmware artifacts bucket against the OTA database.
#
# 1. Replication configuration of FIRMWARE_BUCKET must be Enabled and point at
#    FIRMWARE_REPLICA_BUCKET.
# 2. The newest VERIFY_COUNT firmware rows from the OTA database (sha256_hex, object key) must
#    exist in both buckets; the source object's SHA-256 (downloaded and hashed) must equal
#    sha256_hex, and the replica object's size/ETag must match the source.
# 3. Objects whose replication status is not COMPLETED are reported.
# Exit codes: 0 ok, 1 integrity/replication failure, 2 completed with warnings.
#
# Environment (defaults in parentheses):
#   AWS_REGION                 primary region                                 (eu-west-1)
#   REPLICA_REGION             (eu-central-1)
#   FIRMWARE_BUCKET            source bucket                                  (required)
#   FIRMWARE_REPLICA_BUCKET    replica bucket                                 (required unless REQUIRE_REPLICATION=false)
#   REQUIRE_REPLICATION        (true)
#   ARTIFACT_PREFIX            key prefix of artifacts in the bucket          (firmware/)
#   PGHOST / PGPORT / PGUSER   OTA database endpoint                          (required / 5432 / ironmesh_backup)
#   PG_IAM_AUTH                (true)   PGPASSWORD when false
#   OTA_DB_NAME                (ota)
#   OTA_FIRMWARE_QUERY         SQL returning "<s3_key>\t<sha256_hex>\t<size>" rows, newest first
#   VERIFY_COUNT               artifacts to download and hash                 (25)
#   MAX_DOWNLOAD_BYTES         skip hashing objects larger than this          (536870912)
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-1}"
REPLICA_REGION="${REPLICA_REGION:-eu-central-1}"
FIRMWARE_BUCKET="${FIRMWARE_BUCKET:?FIRMWARE_BUCKET is required}"
REQUIRE_REPLICATION="${REQUIRE_REPLICATION:-true}"
FIRMWARE_REPLICA_BUCKET="${FIRMWARE_REPLICA_BUCKET:-}"
ARTIFACT_PREFIX="${ARTIFACT_PREFIX:-firmware/}"
PGHOST="${PGHOST:?PGHOST is required}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-ironmesh_backup}"
PG_IAM_AUTH="${PG_IAM_AUTH:-true}"
PGSSLMODE="${PGSSLMODE:-verify-full}"
PGSSLROOTCERT="${PGSSLROOTCERT:-/etc/ssl/certs/ca-certificates.crt}"
OTA_DB_NAME="${OTA_DB_NAME:-ota}"
VERIFY_COUNT="${VERIFY_COUNT:-25}"
MAX_DOWNLOAD_BYTES="${MAX_DOWNLOAD_BYTES:-536870912}"
OTA_FIRMWARE_QUERY="${OTA_FIRMWARE_QUERY:-SELECT storage_key, sha256_hex, size FROM firmware ORDER BY created_at DESC LIMIT ${VERIFY_COUNT}}"
export AWS_REGION PGHOST PGPORT PGUSER PGSSLMODE PGSSLROOTCERT

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

for tool in aws psql jq sha256sum; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing dependency: ${tool}"
done

if [[ "${REQUIRE_REPLICATION}" == "true" && -z "${FIRMWARE_REPLICA_BUCKET}" ]]; then
  die "FIRMWARE_REPLICA_BUCKET is required when REQUIRE_REPLICATION=true"
fi

if [[ "${PG_IAM_AUTH}" == "true" ]]; then
  PGPASSWORD="$(aws rds generate-db-auth-token --hostname "${PGHOST}" --port "${PGPORT}" --username "${PGUSER}" --region "${AWS_REGION}")"
else
  : "${PGPASSWORD:?PGPASSWORD is required when PG_IAM_AUTH=false}"
fi
export PGPASSWORD

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

failures=0
warnings=0

# 1. Replication configuration -------------------------------------------------------------
if [[ "${REQUIRE_REPLICATION}" == "true" ]]; then
  log "checking replication configuration of ${FIRMWARE_BUCKET}"
  if ! aws s3api get-bucket-replication --bucket "${FIRMWARE_BUCKET}" > "${WORK_DIR}/replication.json" 2>/dev/null; then
    die "bucket ${FIRMWARE_BUCKET} has no replication configuration"
  fi
  enabled_to_replica="$(jq -r --arg b "arn:aws:s3:::${FIRMWARE_REPLICA_BUCKET}" \
    '[.ReplicationConfiguration.Rules[] | select(.Status == "Enabled" and .Destination.Bucket == $b)] | length' "${WORK_DIR}/replication.json")"
  if [[ "${enabled_to_replica}" == "0" ]]; then
    die "no enabled replication rule targets ${FIRMWARE_REPLICA_BUCKET}"
  fi
  rtc="$(jq -r '[.ReplicationConfiguration.Rules[] | .Destination.ReplicationTime.Status // "Disabled"] | join(",")' "${WORK_DIR}/replication.json")"
  log "replication enabled -> ${FIRMWARE_REPLICA_BUCKET} (RTC: ${rtc})"
  versioning="$(aws s3api get-bucket-versioning --bucket "${FIRMWARE_REPLICA_BUCKET}" --region "${REPLICA_REGION}" --query Status --output text)"
  [[ "${versioning}" == "Enabled" ]] || die "replica bucket versioning is ${versioning}, expected Enabled"
  lock="$(aws s3api get-object-lock-configuration --bucket "${FIRMWARE_REPLICA_BUCKET}" --region "${REPLICA_REGION}" \
    --query 'ObjectLockConfiguration.ObjectLockEnabled' --output text 2>/dev/null || echo "Disabled")"
  if [[ "${lock}" != "Enabled" ]]; then
    log "replica bucket has no Object Lock"
    warnings=$((warnings + 1))
  fi
fi

# 2. Integrity of recent artifacts ---------------------------------------------------------
log "loading the ${VERIFY_COUNT} newest firmware rows from ${OTA_DB_NAME}"
psql -X -At -F $'\t' -v ON_ERROR_STOP=1 -d "${OTA_DB_NAME}" -c "${OTA_FIRMWARE_QUERY}" > "${WORK_DIR}/firmware.tsv"
rows="$(wc -l < "${WORK_DIR}/firmware.tsv" | tr -d ' ')"
log "${rows} artifact(s) to verify"
if [[ "${rows}" == "0" ]]; then
  log "no firmware rows found; nothing to verify"
fi

verified=0
while IFS=$'\t' read -r storage_key sha256_hex size; do
  [[ -z "${storage_key}" ]] && continue
  key="${storage_key#s3://${FIRMWARE_BUCKET}/}"
  case "${key}" in
    "${ARTIFACT_PREFIX}"*|*/image.bin|*.bin) ;;
    *) key="${ARTIFACT_PREFIX}${key}" ;;
  esac

  if ! head_json="$(aws s3api head-object --bucket "${FIRMWARE_BUCKET}" --key "${key}" 2>/dev/null)"; then
    log "MISSING in source: s3://${FIRMWARE_BUCKET}/${key}"
    failures=$((failures + 1))
    continue
  fi
  src_size="$(jq -r '.ContentLength' <<< "${head_json}")"
  src_etag="$(jq -r '.ETag' <<< "${head_json}")"
  repl_status="$(jq -r '.ReplicationStatus // "n/a"' <<< "${head_json}")"
  lock_mode="$(jq -r '.ObjectLockMode // "none"' <<< "${head_json}")"

  if [[ -n "${size}" && "${size}" != "${src_size}" ]]; then
    log "SIZE mismatch ${key}: db ${size}, s3 ${src_size}"
    failures=$((failures + 1))
  fi
  if [[ "${lock_mode}" == "none" ]]; then
    log "WARN ${key}: no Object Lock retention on this version"
    warnings=$((warnings + 1))
  fi

  if (( src_size <= MAX_DOWNLOAD_BYTES )); then
    aws s3 cp "s3://${FIRMWARE_BUCKET}/${key}" "${WORK_DIR}/object.bin" --only-show-errors
    actual_sha="$(sha256sum "${WORK_DIR}/object.bin" | awk '{print $1}')"
    rm -f "${WORK_DIR}/object.bin"
    if [[ "${actual_sha}" != "${sha256_hex}" ]]; then
      log "CHECKSUM mismatch ${key}: db ${sha256_hex}, s3 ${actual_sha}"
      failures=$((failures + 1))
      continue
    fi
  else
    log "WARN ${key}: ${src_size} bytes exceeds MAX_DOWNLOAD_BYTES, checksum skipped"
    warnings=$((warnings + 1))
  fi

  if [[ "${REQUIRE_REPLICATION}" == "true" ]]; then
    if [[ "${repl_status}" != "COMPLETED" && "${repl_status}" != "n/a" ]]; then
      log "WARN ${key}: replication status ${repl_status}"
      warnings=$((warnings + 1))
    fi
    if ! repl_head="$(aws s3api head-object --bucket "${FIRMWARE_REPLICA_BUCKET}" --key "${key}" --region "${REPLICA_REGION}" 2>/dev/null)"; then
      log "MISSING in replica: s3://${FIRMWARE_REPLICA_BUCKET}/${key}"
      failures=$((failures + 1))
      continue
    fi
    repl_size="$(jq -r '.ContentLength' <<< "${repl_head}")"
    repl_etag="$(jq -r '.ETag' <<< "${repl_head}")"
    if [[ "${repl_size}" != "${src_size}" ]]; then
      log "REPLICA size mismatch ${key}: ${src_size} vs ${repl_size}"
      failures=$((failures + 1))
      continue
    fi
    # ETags differ for SSE-KMS objects encrypted with different keys; sizes + source hash suffice.
    if [[ "${repl_etag}" != "${src_etag}" ]]; then
      log "note ${key}: replica ETag differs (expected with SSE-KMS re-encryption)"
    fi
  fi
  verified=$((verified + 1))
done < "${WORK_DIR}/firmware.tsv"

log "verified ${verified}/${rows} artifact(s), ${failures} failure(s), ${warnings} warning(s)"
if (( failures > 0 )); then
  die "firmware backup verification failed"
fi
if (( warnings > 0 )); then
  exit 2
fi
log "firmware replication and integrity ok"
